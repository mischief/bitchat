install_man('bitchat.1')

mandoc = find_program('mandoc', required: false)
if mandoc.found()
  test('man-lint',
    find_program('check-man.sh'),
    args: [files('bitchat.1')],
    suite: 'docs',
  )
endif
