test_packet = executable('test_packet', 'test_packet.c',
  dependencies: [libbitchat_dep],
  include_directories: bitchat_inc,
)
test('packet', test_packet)

test_noise = executable('test_noise', 'test_noise.c',
  dependencies: [libbitchat_dep],
  include_directories: bitchat_inc,
)
test('noise', test_noise)

test_net = executable('test_net', 'test_net.c',
  dependencies: [libbitchat_dep],
  include_directories: bitchat_inc,
)
test('net', test_net, timeout: 60)

test_relay = executable('test_relay', 'test_relay.c',
  dependencies: [libbitchat_dep],
  include_directories: bitchat_inc,
)
test('relay', test_relay)

test_mesh = executable('test_mesh', 'test_mesh.c',
  dependencies: [libbitchat_dep],
  include_directories: bitchat_inc,
)
test('mesh', test_mesh)

if emoji_dep.found()
  test_emoji = executable('test_emoji', 'test_emoji.c',
    dependencies: [emoji_dep],
  )
  test('emoji', test_emoji)
endif

