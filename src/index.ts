import * as path from 'path';
import * as core from '@actions/core';
import * as tc from '@actions/tool-cache';
import * as io from '@actions/io';
import * as os from 'os';
import * as semver from 'semver';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as crypto from 'crypto';
import axios, { isAxiosError } from 'axios';

async function validateSubscription() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  let repoPrivate: boolean | undefined;

  if (eventPath && fs.existsSync(eventPath)) {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8')) as {
      repository?: { private?: boolean };
    };
    repoPrivate = eventData?.repository?.private;
  }

  const upstream = 'open-policy-agent/setup-opa';
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl =
    'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';

  core.info('');
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m');
  core.info(`Secure drop-in replacement for ${upstream}`);
  if (repoPrivate === false)
    core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m');
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
  core.info('');

  if (repoPrivate === false) return;

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const body: Record<string, string> = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      { timeout: 3000 },
    );
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
        `\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`,
      );
      core.error(
        `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`,
      );
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}

// arch in [arm, x32, x64...] (https://nodejs.org/api/os.html#os_os_arch)
// return value in [amd64, 386, arm]
function mapArch(arch: string): string {
  return arch === 'x64' ? 'amd64' : arch;
}

// os in [darwin, linux, win32...] (https://nodejs.org/api/os.html#os_os_platform)
// return value in [darwin, linux, windows]
function mapOS(os: string): string {
  return os === 'win32' ? 'windows' : os;
}

// append static to the filename if requesting the static binary
// opa_linux_arm64_static
function maybeStatic(arch: string, filename: string): string {
  const staticBinary = core.getInput('static') === 'true' || arch === 'arm64'; // For arm64, we only have static binaries
  return staticBinary ? `${filename}_static` : filename;
}

function getDownloadObject(
  version: string,
  mirror: string,
): {
  url: string;
  binaryName: string;
} {
  let vsn = `v${version}`;
  let github = true;
  if (version === 'latest' || version === 'edge') {
    if (mirror !== 'https://github.com') {
      core.warning('Latest or edge versions not supported when mirror is set');
    }
    vsn = version;
    github = false;
  }

  const platform = os.platform();
  const arch = mapArch(os.arch());

  // opa_darwin_amd64
  const filename = `opa_${mapOS(platform)}_${arch}`;
  const binaryName =
    platform === 'win32' ? `${filename}.exe` : maybeStatic(arch, filename);

  let url: string;
  if (github) {
    url = `${mirror}/open-policy-agent/opa/releases/download/${vsn}/${binaryName}`;
  } else {
    url = `https://www.openpolicyagent.org/downloads/${vsn}/${binaryName}`;
  }

  return {
    url,
    binaryName,
  };
}

// Rename opa-<platform>-<arch> to opa
async function renameBinary(
  pathToCLI: string,
  binaryName: string,
): Promise<void> {
  const source = path.join(pathToCLI, binaryName);
  const target = path.join(
    pathToCLI,
    binaryName.endsWith('.exe') ? 'opa.exe' : 'opa',
  );

  core.debug(`Moving ${source} to ${target}.`);
  try {
    await io.mv(source, target);
  } catch (e) {
    core.error(`Unable to move ${source} to ${target}.`);
    throw e;
  }
}

async function getVersion(): Promise<string> {
  const version = core.getInput('version');
  if (version === 'latest' || version === 'edge') {
    return version;
  }

  if (semver.valid(version)) {
    return semver.clean(version) || version;
  }

  if (semver.validRange(version)) {
    const max = semver.maxSatisfying(await getAllVersions(), version);
    if (max) {
      return semver.clean(max) || version;
    }
    core.warning(`${version} did not match any release version.`);
  } else {
    core.warning(`${version} is not a valid version or range.`);
  }
  return version;
}

async function getAllVersions(): Promise<string[]> {
  const githubToken = core.getInput('github-token', { required: true });
  const octokit = github.getOctokit(githubToken);

  const allVersions: string[] = [];
  for await (const response of octokit.paginate.iterator(
    octokit.rest.repos.listReleases,
    { owner: 'open-policy-agent', repo: 'opa' },
  )) {
    for (const release of response.data) {
      if (release.name) {
        allVersions.push(release.name);
      }
    }
  }

  return allVersions;
}

function computeSHA256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function verifyChecksum(
  binaryPath: string,
  checksumUrl: string,
): Promise<void> {
  let checksumFilePath: string;
  try {
    checksumFilePath = await tc.downloadTool(checksumUrl);
  } catch {
    core.info('Checksum file not found, skipping integrity verification.');
    return;
  }

  const expected = fs
    .readFileSync(checksumFilePath, 'utf8')
    .trim()
    .split(/\s+/)[0];
  const actual = await computeSHA256(binaryPath);

  if (actual !== expected) {
    throw new Error(
      `Checksum mismatch for ${path.basename(binaryPath)}: expected ${expected}, got ${actual}`,
    );
  }
  core.info('Checksum verification passed.');
}

async function setup(): Promise<void> {
  try {
    await validateSubscription();
    // Get version of tool to be installed
    const version = await getVersion();
    const mirror = core.getInput('mirror');
    // Download the specific version of the tool, e.g. as a tarball/zipball
    const download = getDownloadObject(version, mirror);
    const pathToCLI = fs.mkdtempSync(path.join(os.tmpdir(), 'tmp'));

    const binaryPath = path.join(pathToCLI, download.binaryName);
    await tc.downloadTool(download.url, binaryPath);
    await verifyChecksum(binaryPath, `${download.url}.sha256`);

    // Make the downloaded file executable
    fs.chmodSync(binaryPath, '755');

    // Rename the platform/architecture specific binary to 'opa' or 'opa.exe'
    await renameBinary(pathToCLI, download.binaryName);

    // Expose the tool by adding it to the PATH
    core.addPath(pathToCLI);

    core.info(`Setup Open Policy Agent CLI version ${version}`);
  } catch (e) {
    core.setFailed(e as string | Error);
  }
}

if (require.main === module) {
  // eslint-disable-next-line no-void
  void setup();
}
