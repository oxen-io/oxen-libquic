local default_deps_old_base = [
  'libevent-dev',
  'libsodium-dev',
  'gnutls-bin',
];
local default_deps_base = default_deps_old_base + [
  'libcli11-dev',
  'libfmt-dev',
  'libspdlog-dev',
  'libgnutls28-dev',
];

local default_deps = ['g++'] + default_deps_base;
local default_deps_old = ['g++'] + default_deps_old_base;
local docker_base = 'registry.oxen.rocks/';

local submodule_commands = [
  'git fetch --tags',
  'git submodule update --init --recursive --depth=1 --jobs=4',
];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodule_commands,
};

// cmake options for static deps mirror
local ci_dep_mirror(want_mirror) = (if want_mirror then ' -DLOCAL_MIRROR=https://oxen.rocks/deps ' else '');

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local kitware_repo(distro) = [
  'eatmydata ' + apt_get_quiet + ' install -y curl ca-certificates',
  'curl -sSL https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - >/usr/share/keyrings/kitware-archive-keyring.gpg',
  'echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ ' + distro + ' main" >/etc/apt/sources.list.d/kitware.list',
  'eatmydata ' + apt_get_quiet + ' update',
];

local debian_backports(distro, pkgs) = [
  'echo deb http://deb.debian.org/debian ' + distro + '-backports main >>/etc/apt/sources.list.d/backports.list',
  'eatmydata ' + apt_get_quiet + ' update',
  'eatmydata ' + apt_get_quiet + ' install -y ' + std.join(' ', std.map(function(p) p + '/' + distro + '-backports', pkgs)),
];

local local_gnutls(jobs=6, prefix='/usr/local') = [
  apt_get_quiet + ' install -y curl ca-certificates',
  'curl -sSL https://ftp.gnu.org/gnu/nettle/nettle-3.9.1.tar.gz | tar xfz -',
  'curl -sSL https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.0.tar.xz | tar xfJ -',
  'export CC="ccache gcc"',
  'export PKG_CONFIG_PATH=' + prefix + '/lib/pkgconfig:' + prefix + '/lib64/pkgconfig',
  'export LD_LIBRARY_PATH=' + prefix + '/lib:' + prefix + '/lib64',
  'cd nettle-3.9.1',
  './configure --prefix=' + prefix,
  'make -j' + jobs,
  'make install',
  'cd ..',
  'cd gnutls-3.8.0',
  './configure --prefix=' + prefix + ' --with-included-libtasn1 --with-included-unistring --without-p11-kit  --disable-libdane --disable-cxx --without-tpm --without-tpm2',
  'make -j' + jobs,
  'make install',
  'cd ..',
];


local generic_build(jobs, build_type, lto, werror, cmake_extra, local_mirror, tests, test_0rtt=true, gdb=true)
      = [
          'mkdir build',
          'cd build',
          'cmake .. -DCMAKE_COLOR_DIAGNOSTICS=ON -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
          (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
          '-DWITH_LTO=' + (if lto then 'ON ' else 'OFF ') +
          '-DLIBQUIC_BUILD_TESTS=' + (if tests then 'ON ' else 'OFF ') +
          cmake_extra +
          ci_dep_mirror(local_mirror),
          'make -j' + jobs + ' VERBOSE=1',
          'cd ..',
        ]
        + (if tests then [
             'cd build',
             (if gdb then '../utils/ci/drone-gdb.sh ' else '') + './tests/alltests --success -T --log-level debug --no-ipv6 --colour-mode ansi' + (if test_0rtt then '' else ' --disable-0rtt'),
             'cd ..',
           ] else []);

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      extra_setup=[],
                      build_type='Release',
                      lto=false,
                      werror=true,
                      cmake_extra='',
                      local_mirror=true,
                      extra_cmds=[],
                      jobs=6,
                      tests=true,
                      test_0rtt=true,
                      oxen_repo=false,
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                  apt_get_quiet + ' update',
                  apt_get_quiet + ' install -y eatmydata',
                ] + (
                  if oxen_repo then [
                    'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
                    'cp utils/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
                    'echo deb http://deb.oxen.io $$(lsb_release -sc) main >/etc/apt/sources.list.d/oxen.list',
                    'eatmydata ' + apt_get_quiet + ' update',
                  ] else []
                ) + extra_setup
                + [
                  'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                  'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y cmake git pkg-config ccache ' + std.join(' ', deps),
                ]
                + generic_build(jobs, build_type, lto, werror, cmake_extra, local_mirror, tests, test_0rtt=test_0rtt)
                + extra_cmds,
    },
  ],
};
// windows cross compile on debian
local windows_cross_pipeline(name,
                             image,
                             arch='amd64',
                             build_type='Release',
                             lto=false,
                             werror=false,
                             cmake_extra='',
                             local_mirror=true,
                             extra_cmds=[],
                             jobs=6,
                             tests=true,
                             test_0rtt=true,
                             allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, WINDOWS_BUILD_NAME: 'x64' },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y build-essential cmake git pkg-config ccache g++-mingw-w64-x86-64-posix',
        'mkdir build',
        'cd build',
        'cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/cross/mingw-x64.cmake -DBUILD_STATIC_DEPS=ON ' +
        '-DCMAKE_COLOR_DIAGNOSTICS=ON -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        '-DWITH_LTO=' + (if lto then 'ON ' else 'OFF ') +
        '-DLIBQUIC_BUILD_TESTS=' + (if tests then 'ON ' else 'OFF ') +
        ci_dep_mirror(local_mirror),
        'make -j' + jobs + ' VERBOSE=1',
      ] + extra_cmds,
    },
    {
      name: 'tests (via wine)',
      image: image,
      pull: 'always',
      //[if allow_fail then 'failure']: 'ignore',
      // Currently fails, but ignore for now as running-under-wine is not really a first-tier
      // supported platform:
      failure: 'ignore',
      environment: { WINEDEBUG: '-all' },
      commands: [
        'cd build/tests',
        'wine-stable alltests.exe --success -T --log-level debug --colour-mode ansi --no-ipv6'
        + (if test_0rtt then '' else ' --disable-0rtt'),
      ],
    },
  ],
};

// linux cross compile on debian
local linux_cross_pipeline(name,
                           cross_targets,
                           arch='amd64',
                           build_type='Release',
                           cmake_extra='',
                           local_mirror=true,
                           extra_cmds=[],
                           jobs=6,
                           tests=true,
                           allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: docker_base + 'debian-stable-cross',
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, CROSS_TARGETS: std.join(':', cross_targets) },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'VERBOSE=1 JOBS=' + jobs + ' ./contrib/cross.sh ' + std.join(' ', cross_targets) +
        ' -- ' + cmake_extra + ci_dep_mirror(local_mirror),
      ],
    },
  ],
};

local clang(version) = debian_pipeline(
  'Debian sid/clang-' + version,
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_base,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' '
);

local full_llvm(version, _allow_fail=false) = debian_pipeline(
  'Debian sid/llvm-' + version,
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version, ' lld-' + version, ' libc++-' + version + '-dev', 'libc++abi-' + version + '-dev']
       + default_deps_base,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version +
              ' -DCMAKE_CXX_COMPILER=clang++-' + version +
              ' -DCMAKE_CXX_FLAGS=-stdlib=libc++ ' +
              std.join(' ', [
                '-DCMAKE_' + type + '_LINKER_FLAGS=-fuse-ld=lld-' + version
                for type in ['EXE', 'MODULE', 'SHARED']
              ]) +
              ' -DOXEN_LOGGING_FORCE_SUBMODULES=ON',
  allow_fail=_allow_fail
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  arch='amd64',
                  werror=true,
                  lto=false,
                  cmake_extra='',
                  local_mirror=true,
                  extra_cmds=[],
                  jobs=6,
                  tests=true,
                  test_0rtt=true,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: arch },
  steps: [
    { name: 'submodules', commands: submodule_commands },
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  // If you don't do this then the C compiler doesn't have an include path containing
                  // basic system headers.  WTF apple:
                  'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
                ]
                + generic_build(jobs, build_type, lto, werror, cmake_extra, local_mirror, tests, test_0rtt=test_0rtt, gdb=false)
                + extra_cmds,
    },
  ],
};


[
  {
    name: 'lint check',
    kind: 'pipeline',
    type: 'docker',
    steps: [{
      name: 'build',
      image: docker_base + 'lint',
      pull: 'always',
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git clang-format-19 jsonnet',
        './utils/ci/lint-check.sh',
      ],
    }],
  },

  // Various debian builds
  debian_pipeline('Debian sid', docker_base + 'debian-sid'),
  debian_pipeline('Debian sid/Debug', docker_base + 'debian-sid', build_type='Debug'),
  clang(17),
  full_llvm(17),
  clang(19),
  full_llvm(19),
  debian_pipeline('Debian sid -GSO', docker_base + 'debian-sid', cmake_extra='-DLIBQUIC_SEND=sendmmsg'),
  debian_pipeline('Debian sid -mmsg', docker_base + 'debian-sid', cmake_extra='-DLIBQUIC_SEND=sendmsg -DLIBQUIC_RECVMMSG=OFF'),
  debian_pipeline('Debian sid -GSO/Debug', docker_base + 'debian-sid', build_type='Debug', cmake_extra='-DLIBQUIC_SEND=sendmmsg'),
  debian_pipeline('Debian sid -mmsg/Debug', docker_base + 'debian-sid', build_type='Debug', cmake_extra='-DLIBQUIC_SEND=sendmsg -DLIBQUIC_RECVMMSG=OFF'),
  debian_pipeline('Debian 11 -mmsg', docker_base + 'debian-bullseye', deps=default_deps_old, extra_setup=local_gnutls() + debian_backports('bullseye', ['cmake']), cmake_extra='-DLIBQUIC_SEND=sendmsg -DLIBQUIC_RECVMMSG=OFF'),
  debian_pipeline('Debian 11 -mmsg/Debug', docker_base + 'debian-bullseye', deps=default_deps_old, extra_setup=local_gnutls() + debian_backports('bullseye', ['cmake']), cmake_extra='-DLIBQUIC_SEND=sendmsg -DLIBQUIC_RECVMMSG=OFF', build_type='Debug'),
  debian_pipeline('Debian testing (i386)', docker_base + 'debian-testing/i386'),
  debian_pipeline('Debian 12 static', docker_base + 'debian-bookworm', cmake_extra='-DBUILD_STATIC_DEPS=ON', deps=['g++']),
  debian_pipeline('Debian 12 bookworm (i386)', docker_base + 'debian-bookworm/i386'),
  debian_pipeline('Debian 11 bullseye', docker_base + 'debian-bullseye', deps=['g++'], extra_setup=local_gnutls() + debian_backports('bullseye', ['cmake'])),
  debian_pipeline('Debian 11 static Debug', docker_base + 'debian-bullseye', build_type='Debug', cmake_extra='-DBUILD_STATIC_DEPS=ON', deps=default_deps_old, extra_setup=debian_backports('bullseye', ['cmake'])),
  debian_pipeline('Ubuntu latest', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Ubuntu 22.04 jammy', docker_base + 'ubuntu-jammy'),
  debian_pipeline('Ubuntu 20.04 focal', docker_base + 'ubuntu-focal', deps=['g++-10'] + default_deps_old, extra_setup=kitware_repo('focal') + local_gnutls(), cmake_extra='-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', jobs=4),
  debian_pipeline('Debian stable/Debug (ARM64)', docker_base + 'debian-stable', arch='arm64', jobs=4, build_type='Debug', test_0rtt=false),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64', jobs=4),

  // Windows builds (x64)
  windows_cross_pipeline('Windows (x64)', docker_base + 'debian-win32-cross', test_0rtt=false),

  // Macos builds:
  mac_builder('macOS (Release, ARM)', arch='arm64'),
  mac_builder('macOS (Debug, ARM)', arch='arm64', build_type='Debug', test_0rtt=false),
  mac_builder('macOS (Static, ARM)',
              cmake_extra='-DBUILD_STATIC_DEPS=ON',
              lto=true,
              arch='arm64'),
  mac_builder('macOS (Release, Intel)'),
  mac_builder('macOS (Debug, Intel)', build_type='Debug', test_0rtt=false),
  mac_builder('macOS (Static, Intel)',
              cmake_extra='-DBUILD_STATIC_DEPS=ON',
              lto=true),
]
