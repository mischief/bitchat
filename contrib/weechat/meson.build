# Built only when weechat's plugin header is installed.
weechat_inc = cc.has_header('weechat/weechat-plugin.h')

if weechat_inc
  shared_module('bitchat', 'bitchat-weechat.c',
    dependencies: [libbitchat_dep],
    include_directories: bitchat_inc,
    name_prefix: '',
    install: true,
    install_dir: get_option('libdir') / 'weechat' / 'plugins',
  )
else
  warning('weechat-plugin.h not found: skipping the weechat plugin')
endif
