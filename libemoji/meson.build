# :shortcode: -> UTF-8 glyph. Vendored from clm; no curses or bitchat
# dependency, and lua is needed only to generate the table at build time.
lua_bin = find_program('lua5.4', 'lua54', 'lua', required: false, native: true)

emoji_inc = include_directories('.')

if lua_bin.found()
  emoji_data = custom_target('emoji_data.c',
    input: files('emoji_data.tsv'),
    output: 'emoji_data.c',
    command: [lua_bin, files('gen_emoji.lua'), '@OUTPUT@', '@INPUT@'],
  )

  emoji_lib = static_library('emoji',
    files('emoji.c'), emoji_data,
    include_directories: emoji_inc,
  )

  emoji_dep = declare_dependency(
    link_with: emoji_lib,
    include_directories: emoji_inc,
    compile_args: ['-DHAVE_EMOJI'],
  )
else
  warning('lua not found: building without :shortcode: expansion')
  emoji_dep = dependency('', required: false)
endif
