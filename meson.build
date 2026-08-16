project('bitchat', 'c',
  version: '0.1',
  license: 'ISC',
  meson_version: '>=1.1',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=true',
  ])

cc = meson.get_compiler('c')

add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')
add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-fno-omit-frame-pointer', language: 'c')

hardening_args = [
  '-Wnull-dereference',
  '-Warray-bounds',
  '-Wsign-conversion',
  '-Wfloat-equal',
  '-Wformat',
  '-Wformat-security',
  '-Wuninitialized',
  '-Wshadow',
  '-Wimplicit-fallthrough',
  '-Wswitch',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Wmissing-declarations',
  '-Wvla',
  '-Walloca',
  '-Wshift-overflow',
  '-Wframe-larger-than=2048',
  '-Wreturn-stack-address',
  '-fsanitize-trap=all',
]

foreach a : hardening_args
  if cc.has_argument(a)
    add_project_arguments(a, language: 'c')
  endif
endforeach

suppress_args = ['-Wno-unused-parameter']

foreach a : suppress_args
  if cc.has_argument(a)
    add_project_arguments(a, language: 'c')
  endif
endforeach

bitchat_inc = include_directories('.')

libcrypto_dep = dependency('libcrypto', version: '>=3.0')
zlib_dep = dependency('zlib')
libsystemd_dep = dependency('libsystemd')
curses_dep = dependency('ncursesw', required: false)
if not curses_dep.found()
  curses_dep = dependency('ncurses')
endif

configure_file(
  input: 'bitchat/version.h.in',
  output: 'version.h',
  configuration: {'VERSION': meson.project_version()},
  install: true,
  install_dir: get_option('includedir') / 'bitchat',
)

subdir('libemoji')
subdir('lib')
subdir('src')
subdir('man')
subdir('contrib/weechat')

if get_option('tests')
  subdir('test')
endif

all_sources = files(
  'lib/ble.c', 'lib/crypto.c', 'lib/identity.c', 'lib/internal.h',
  'lib/mesh.c', 'lib/noise.c', 'lib/packet.c', 'lib/tlv.c', 'lib/util.c',
  'src/main.c', 'src/ui.c', 'src/ui.h',
  'bitchat/ble.h', 'bitchat/crypto.h', 'bitchat/identity.h', 'bitchat/mesh.h',
  'bitchat/noise.h', 'bitchat/packet.h', 'bitchat/tlv.h',
  'test/test_packet.c', 'test/test_noise.c', 'test/test_mesh.c',
)

clang_format = find_program('clang-format', required: false)
if clang_format.found()
  run_target('clang-format', command: [clang_format, '-i', all_sources])
  run_target('clang-format-check',
    command: [clang_format, '--dry-run', '-Werror', all_sources])
endif

clang_tidy = find_program('clang-tidy', required: false)
if clang_tidy.found()
  run_target('clang-tidy',
    command: [clang_tidy, '-p', meson.project_build_root(), all_sources])
endif

cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
  run_target('cppcheck',
    command: [
      cppcheck,
      '--project=' + meson.project_build_root() / 'compile_commands.json',
      '--enable=warning,style,performance,portability',
      '--std=' + get_option('c_std'),
      '--suppress=normalCheckLevelMaxBranches',
      # cppcheck does not model __attribute__((cleanup)), so autofree
      # pointers look leaked, and it cannot parse the ncurses headers.
      '--suppress=memleak',
      '--suppress=unknownMacro',
      '--suppress=constParameterCallback',
      '--error-exitcode=1',
    ],
  )
endif
