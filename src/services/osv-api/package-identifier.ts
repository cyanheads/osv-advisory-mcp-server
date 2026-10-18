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

/** Canonical matcher coordinate plus the unchanged upstream PURL, when supplied. */
export interface ResolvedPackage {
  ecosystem: string;
  /** Omit the separate upstream version when it was embedded in the PURL. */
  embeddedVersion?: boolean;
  name: string;
  purl?: string;
  version: string;
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

/** Preserve tuple behavior and resolve a PURL without changing its upstream spelling. */
export function resolvePackage(input: PackageIdentifier): ResolvedPackage {
  if (input.purl === undefined) return input;
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
  return {
    name,
    ecosystem,
    version,
    purl: input.purl,
    embeddedVersion: Boolean(parsed.version),
  };
}

/** OSV wire query identity, keeping PURL and separate-version semantics intact. */
export function packageBody(pkg: ResolvedPackage) {
  return pkg.purl === undefined
    ? { package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version }
    : { package: { purl: pkg.purl }, ...(pkg.embeddedVersion ? {} : { version: pkg.version }) };
}
