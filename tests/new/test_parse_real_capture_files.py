from pcapng.scanner import FileScanner


def test_sample_test001_ntar():
    with open('test_data/test001.ntar') as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # There is just a section header
        assert len(blocks) == 1


def test_sample_test002_ntar():
    with open('test_data/test002.ntar') as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2


def test_sample_test003_ntar():
    with open('test_data/test003.ntar') as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2


def test_sample_test004_ntar():
    with open('test_data/test004.ntar') as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header
        assert len(blocks) == 1


def test_sample_test005_ntar():
    with open('test_data/test005.ntar') as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2


def test_sample_test006_ntar():
    with open('test_data/test006.ntar') as fp:
        scanner = FileScanner(fp)
        list(scanner)

        # WARNING: Something is broken with this file
        # dig further and write more tests


def test_sample_test007_ntar():
    with open('test_data/test007.ntar') as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test008_ntar():
    with open('test_data/test008.ntar') as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test009_ntar():
    with open('test_data/test009.ntar') as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test010_ntar():
    with open('test_data/test010.ntar') as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass
