libbitchat_src = files(
  'crypto.c',
  'identity.c',
  'mesh.c',
  'noise.c',
  'packet.c',
  'tcp.c',
  'tlv.c',
  'util.c',
  'ble.c',
)

libbitchat_deps = [libcrypto_dep, zlib_dep, libsystemd_dep]

libbitchat = library('bitchat', libbitchat_src,
  dependencies: libbitchat_deps,
  include_directories: bitchat_inc,
  install: true,
  soversion: 0,
  c_args: ['-fvisibility=hidden', '-DBITCHAT_BUILDING'],
  link_args: [
    '-Wl,--version-script=' + meson.current_source_dir() / 'libbitchat.map',
  ],
  link_depends: files('libbitchat.map'),
)

libbitchat_dep = declare_dependency(
  link_with: libbitchat,
  include_directories: bitchat_inc,
  dependencies: libbitchat_deps,
)

install_headers(
  '../bitchat/ble.h',
  '../bitchat/crypto.h',
  '../bitchat/export.h',
  '../bitchat/identity.h',
  '../bitchat/mesh.h',
  '../bitchat/noise.h',
  '../bitchat/packet.h',
  '../bitchat/tcp.h',
  '../bitchat/tlv.h',
  subdir: 'bitchat',
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(libbitchat)
