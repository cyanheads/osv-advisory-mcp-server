/**
 * @fileoverview Translate standards-parsed PURLs using OSV's Go PURL registry.
 * @module services/osv-api/package-identifier
 */
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { PackageURL } from 'packageurl-js';

/** The two accepted package-version identifiers. */
export type PackageIdentifier =
  | { name: string; ecosystem: string; version: string; purl?: never }
  | { purl: string; version?: string | undefined; name?: never; ecosystem?: never };

/** Matcher coordinate plus original and, when normalized, wire PURL identities. */
export interface ResolvedPackage {
  ecosystem: string;
  /** Omit the separate upstream version when it was embedded in the PURL. */
  embeddedVersion?: boolean;
  name: string;
  purl?: string;
  version: string;
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
const DEBIAN_VERSIONS: Record<string, string> = {
  buzz: '1.1',
  rex: '1.2',
  bo: '1.3',
  hamm: '2',
  slink: '2.1',
  potato: '2.2',
  woody: '3',
  sarge: '3.1',
  etch: '4',
  lenny: '5',
  squeeze: '6',
  wheezy: '7',
  jessie: '8',
  stretch: '9',
  buster: '10',
  bullseye: '11',
  bookworm: '12',
  trixie: '13',
  forky: '14',
  duke: '15',
};

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

/** Resolve exact versions while preserving original package and PURL spelling for echoes. */
export function resolvePackage(input: PackageIdentifier): ResolvedPackage {
  if (input.purl === undefined)
    return { ...input, version: exactVersion(input.version, input.ecosystem) };
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
  if (
    parsed.namespace &&
    ['npm', 'hex', 'swift', 'golang', 'maven', 'gradle'].includes(parsed.type)
  ) {
    name = `${parsed.namespace}${['maven', 'gradle'].includes(parsed.type) ? ':' : '/'}${name}`;
  }
  if (parsed.type === 'golang' && parsed.subpath) name += `/${parsed.subpath}`;
  if (ecosystem === 'Debian' && parsed.qualifiers?.distro) {
    const distro = parsed.qualifiers.distro.toLowerCase();
    ecosystem += `:${Object.hasOwn(DEBIAN_VERSIONS, distro) ? DEBIAN_VERSIONS[distro] : distro}`;
  }
  const normalizedVersion = exactVersion(version, ecosystem);
  if (parsed.version && normalizedVersion !== version) parsed.version = normalizedVersion;
  return {
    name,
    ecosystem,
    version: normalizedVersion,
    purl: input.purl,
    embeddedVersion: Boolean(parsed.version),
    ...(parsed.version && normalizedVersion !== version ? { wirePurl: parsed.toString() } : {}),
  };
}

/** OSV wire query identity, keeping PURL and separate-version semantics intact. */
export function packageBody(pkg: ResolvedPackage) {
  return pkg.purl === undefined
    ? { package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version }
    : {
        package: { purl: pkg.wirePurl ?? pkg.purl },
        ...(pkg.embeddedVersion ? {} : { version: pkg.version }),
      };
}
