from unifiwifioptimizer.cli.exit_codes import ExitCode


def test_exit_code_values_are_the_documented_contract() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "UNEXPECTED_ERROR": 1,
        "USAGE": 2,
        "CONFIG": 3,
        "TLS": 4,
        "HOST_KEY": 5,
        "PARTIAL": 6,
        "ENVIRONMENT": 7,
        "INTERRUPTED": 130,
    }
