from pcapng.objects import Options


# Little-endian, hand-written, options!
HANDCRAFTED_OPTIONS = [(
    "\x01\x00\x0B\x00Hello world\x00"  # Comment: hello world!
    "\x00\x00\x00\x00"
), (
    "\x01\x00\x0B\x00Hello world\x00"
    "\x01\x00\x17\x00This is another comment\x00"
    "\x02\xff\x0d\x00Example value\x00\x00\x00"
    "\x00\x00\x00\x00"
)]


def test_handcrafted_options_0():
    opts = Options.unpack(
        HANDCRAFTED_OPTIONS[0],
        names={'comment': 0x0001},
        endianness=1)

    assert len(opts) == 1
    assert opts['comment'] == 'Hello world'
    assert opts.get_values('comment') == ['Hello world']

    assert opts.pack(endianness=1) == HANDCRAFTED_OPTIONS[0]


def test_handcrafted_options_1():
    opts = Options.unpack(
        HANDCRAFTED_OPTIONS[1],
        names={'comment': 0x0001, 'example': 0xff02},
        endianness=1)

    assert len(opts) == 2
    assert opts['comment'] == 'Hello world'
    assert opts['example'] == 'Example value'
    assert opts.get_values('comment') == [
        'Hello world', 'This is another comment']

    assert opts.pack(endianness=1) == HANDCRAFTED_OPTIONS[1]


def test_create_handcrafted_0():
    opts = Options()
    opts.field_names = {'comment': 0x01}
    opts['comment'] = 'Hello world'

    assert opts.pack(endianness=1) == HANDCRAFTED_OPTIONS[0]


def test_create_handcrafted_1():
    opts = Options()
    opts.field_names = {'comment': 0x0001, 'example': 0xff02}
    opts.add_value('comment', 'Hello world')
    opts.add_value('comment', 'This is another comment')
    opts.add_value('example', 'Example value')

    assert opts.pack(endianness=1) == HANDCRAFTED_OPTIONS[1]


def test_delete_option():
    opts = Options()
    opts.field_names = {'comment': 0x0001, 'example': 0xff02}
    opts.add_value('comment', 'Hello world')
    opts.add_value('comment', 'This is another comment')

    assert opts.pack(endianness=1) == (
        "\x01\x00\x0B\x00Hello world\x00"
        "\x01\x00\x17\x00This is another comment\x00"
        "\x00\x00\x00\x00")

    del opts['comment']

    assert opts.pack(endianness=1) == "\x00\x00\x00\x00"


def test_iterate_options():
    opts = Options()

    opts[0x0001] = 'Hello world'
    opts[0x0002] = 'This is an example'
    opts[0x0003] = 'Just another example'

    assert sorted(iter(opts)) == [1, 2, 3]

    opts.field_names = {'comment': 0x0001}
    assert sorted(iter(opts)) == [2, 3, 'comment']

    opts.field_names = {'comment': 0x0001, 'foobar': 0xff00}
    assert sorted(iter(opts)) == [2, 3, 'comment']

    opts.field_names = {'comment': 0x0001, 'foobar': 0xff00, 'ex2': 0x0002}
    assert sorted(iter(opts)) == [0x0003, 'comment', 'ex2']
