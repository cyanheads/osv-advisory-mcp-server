/**
 * @fileoverview Translate standards-parsed PURLs using OSV's Go PURL registry.
 * @module services/osv-api/package-identifier
 */
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { PackageURL } from 'packageurl-js';
import { canonicalEcosystem } from './ecosystem-catalog.js';

/** The two accepted package-version identifiers. */
export type PackageIdentifier =
  | { name: string; ecosystem: string; version: string; purl?: never }
  | { purl: string; version?: string | undefined; name?: never; ecosystem?: never };

/** Matcher coordinate plus original PURL and optional native PURL wire identity. */
export interface ResolvedPackage {
  ecosystem: string;
  /** Omit the separate upstream version when it was embedded in the PURL. */
  embeddedVersion?: boolean;
  name: string;
  purl?: string;
  version: string;
  /** Absent when the effective coordinate must be sent as a tuple. */
  wirePurl?: string;
}

const ECOSYSTEMS: Record<string, string> = {
  bitnami: 'Bitnami',
  cran: 'CRAN',
  conan: 'ConanCenter',
  hackage: 'Hackage',
  hex: 'Hex',
  julia: 'Julia',
  nuget: 'NuGet',
  generic: 'OSS-Fuzz',
  pub: 'Pub',
  pypi: 'PyPI',
  gem: 'RubyGems',
  swift: 'SwiftURL',
  cargo: 'crates.io',
  npm: 'npm',
  opam: 'opam',
  dhi: 'Docker Hardened Images',
  golang: 'Go',
  maven: 'Maven',
  gradle: 'Maven',
  'apk/chainguard': 'Chainguard',
  composer: 'Packagist',
  'apk/minimos': 'MinimOS',
  'apk/wolfi': 'Wolfi',
  'deb/echo': 'Echo',
  'deb/ubuntu': 'Ubuntu',
  'deb/debian': 'Debian',
  'rpm/almalinux': 'AlmaLinux',
  'rpm/azure-linux': 'Azure Linux',
  'rpm/mageia': 'Mageia',
  'rpm/openeuler': 'openEuler',
  'rpm/opensuse': 'openSUSE',
  'rpm/redhat': 'Red Hat',
  'rpm/rocky-linux': 'Rocky Linux',
  'rpm/suse': 'SUSE',
  'apk/alpaquita': 'Alpaquita',
  'apk/alpine': 'Alpine',
  'apk/bellsoft-hardened-containers': 'BellSoft Hardened Containers',
  'apk/dhi': 'Docker Hardened Images',
  'deb/dhi': 'Docker Hardened Images',
};
const DEBIAN_VERSIONS = new Map([
  ['buzz', '1.1'],
  ['rex', '1.2'],
  ['bo', '1.3'],
  ['hamm', '2'],
  ['slink', '2.1'],
  ['potato', '2.2'],
  ['woody', '3'],
  ['sarge', '3.1'],
  ['etch', '4'],
  ['lenny', '5'],
  ['squeeze', '6'],
  ['wheezy', '7'],
  ['jessie', '8'],
  ['stretch', '9'],
  ['buster', '10'],
  ['bullseye', '11'],
  ['bookworm', '12'],
  ['trixie', '13'],
  ['forky', '14'],
  ['duke', '15'],
]);
const DEBIAN_RELEASES = new Set(DEBIAN_VERSIONS.values());

/** OSV accepts leading zeros in exact numeric components for npm and crates.io. */
function numericIdentifier(value: string): boolean {
  return value.length > 0 && !/[^0-9]/.test(value);
}

/** Validate exact SemVer-shaped versions with linear scans, retaining OSV's leading-zero compatibility. */
function isSemver(version: string): boolean {
  const value = version.startsWith('v') ? version.slice(1) : version;
  const plus = value.indexOf('+');
  const build = plus < 0 ? undefined : value.slice(plus + 1);
  if (
    build !== undefined &&
    !build.split('.').every((part) => part.length > 0 && !/[^0-9A-Za-z-]/.test(part))
  )
    return false;
  const release = plus < 0 ? value : value.slice(0, plus);
  const dash = release.indexOf('-');
  const core = dash < 0 ? release : release.slice(0, dash);
  const numbers = core.split('.');
  if (numbers.length !== 3 || !numbers.every(numericIdentifier)) return false;
  if (dash < 0) return true;
  return release
    .slice(dash + 1)
    .split('.')
    .every((part) => part.length > 0 && !/[^0-9A-Za-z-]/.test(part));
}

/** Reject only constraints whose meaning is established for this ecosystem. */
function exactVersion(version: string, ecosystem: string): string {
  let normalized = version;
  let invalid = false;
  if (ecosystem === 'npm' || ecosystem === 'crates.io') {
    normalized = version.startsWith('==')
      ? version.slice(2)
      : version.startsWith('=')
        ? version.slice(1)
        : version;
    invalid = !isSemver(normalized);
  } else if (PEP_503_VERSION_ECOSYSTEMS.has(ecosystem)) {
    invalid = /^[<>=!~]/.test(version);
  } else if (ecosystem === 'RubyGems') {
    invalid = /^[<>=!~]/.test(version);
  } else if (ecosystem === 'Maven') {
    invalid = version.startsWith('[') || version.startsWith('(');
  }
  if (invalid)
    throw validationError(
      'Pass the exact resolved version from the lockfile, such as 4.17.20, not a range or constraint.',
      { reason: 'invalid_version' },
    );
  return normalized;
}

const PEP_503_VERSION_ECOSYSTEMS = new Set(['PyPI', 'Echo:PyPI', 'Red Hat Lightwell:PyPI']);

function alpineReleaseRequired(): never {
  throw validationError('Provide the Alpine release branch as Alpine:v<major>.<minor>.', {
    reason: 'alpine_release_required',
  });
}

function mavenName(name: string): string {
  const parts = /^([^:/\s]+)[:/]([^:/\s]+)$/.exec(name);
  if (!parts || parts[0].length !== name.length)
    throw validationError('Provide the Maven name as groupId:artifactId.', {
      reason: 'invalid_maven_name',
    });
  return `${parts[1]}:${parts[2]}`;
}

/** Resolve the effective query coordinate and retain the caller's original PURL for echoes. */
export function resolvePackage(input: PackageIdentifier): ResolvedPackage {
  if (input.purl === undefined) {
    const ecosystem = canonicalEcosystem(input.ecosystem);
    const version = exactVersion(input.version, ecosystem);
    if (ecosystem === 'Alpine' || ecosystem === 'Alpine:') alpineReleaseRequired();
    const name =
      ecosystem === 'Maven' || ecosystem.startsWith('Maven:') ? mavenName(input.name) : input.name;
    return { name, ecosystem, version };
  }
  let parsed: PackageURL;
  try {
    parsed = PackageURL.fromString(input.purl);
  } catch (cause) {
    throw validationError(
      'Malformed PURL. Provide a complete pkg:type/name@version URL, or a versionless PURL with a separate version.',
      { reason: 'invalid_purl' },
      { cause },
    );
  }
  const namespacedType = `${parsed.type}/${parsed.namespace ?? ''}`;
  let ecosystem = Object.hasOwn(ECOSYSTEMS, namespacedType)
    ? ECOSYSTEMS[namespacedType]
    : Object.hasOwn(ECOSYSTEMS, parsed.type)
      ? ECOSYSTEMS[parsed.type]
      : undefined;
  if (!ecosystem)
    throw validationError(
      'This PURL type or namespace is not supported by OSV. Use a supported PURL or the name/ecosystem/version tuple.',
      { reason: 'unsupported_purl' },
    );
  const version = parsed.version ?? input.version;
  if (!version || (parsed.version !== undefined && input.version !== undefined)) {
    throw validationError(
      'Provide exactly one version: embedded in the PURL or separate, never both or neither.',
      { reason: 'invalid_purl_version' },
    );
  }
  let name = parsed.name;
  if (parsed.namespace && ['npm', 'hex', 'swift', 'golang', 'composer'].includes(parsed.type)) {
    name = `${parsed.namespace}/${name}`;
  }
  if (ecosystem === 'Maven') {
    name = mavenName(`${parsed.namespace ?? ''}:${name}`);
  }
  if (parsed.type === 'golang' && parsed.subpath) name += `/${parsed.subpath}`;
  const distro = parsed.qualifiers?.distro;
  if (ecosystem === 'Alpine') {
    const branch = /^(?:alpine-)?v?([0-9]+\.[0-9]+)(?:\.[0-9]+)?$/.exec(distro ?? '');
    if (!branch || branch[0] !== distro) alpineReleaseRequired();
    return {
      name,
      ecosystem: `Alpine:v${branch[1]}`,
      version,
      purl: input.purl,
    };
  }
  if (ecosystem === 'Ubuntu' && distro) {
    const release = /^(?:ubuntu-)?([0-9]{2}\.[0-9]{2})(?:\.[0-9]+)?$/.exec(distro);
    if (release && release[0] === distro) {
      return {
        name,
        ecosystem: `Ubuntu:${release[1]}`,
        version,
        purl: input.purl,
        embeddedVersion: parsed.version !== undefined,
      };
    }
  }
  if (ecosystem === 'Packagist' && parsed.qualifiers?.repository_url)
    ecosystem += `:${parsed.qualifiers.repository_url}`;
  let wirePurl = input.purl;
  if (ecosystem === 'Debian' && distro) {
    const folded = distro.toLowerCase();
    const prefixed = folded.startsWith('debian-');
    const release = prefixed ? folded.slice('debian-'.length) : folded;
    const canonical = DEBIAN_VERSIONS.get(release) ?? release;
    if (!DEBIAN_RELEASES.has(canonical)) {
      throw validationError(
        'Provide a Debian major release or codename, such as debian-12 or bookworm, or use a release-qualified tuple such as Debian:12.',
        { reason: 'invalid_debian_distro' },
      );
    }
    ecosystem += `:${canonical}`;
    if (prefixed) {
      parsed.qualifiers = { ...parsed.qualifiers, distro: canonical };
      wirePurl = parsed.toString();
    }
  }
  const normalizedVersion = exactVersion(version, ecosystem);
  if (parsed.version && normalizedVersion !== version) {
    parsed.version = normalizedVersion;
    wirePurl = parsed.toString();
  }
  return {
    name,
    ecosystem,
    version: normalizedVersion,
    purl: input.purl,
    embeddedVersion: Boolean(parsed.version),
    wirePurl,
  };
}

/** OSV wire query identity, keeping PURL and separate-version semantics intact. */
export function packageBody(pkg: ResolvedPackage) {
  return pkg.wirePurl === undefined
    ? { package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version }
    : {
        package: { purl: pkg.wirePurl },
        ...(pkg.embeddedVersion ? {} : { version: pkg.version }),
      };
}
