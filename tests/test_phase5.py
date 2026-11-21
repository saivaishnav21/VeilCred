from veilcred.attacks import run_all


def test_every_attack_is_defeated_and_the_control_passes():
    results = run_all()
    failed = [(r.name, r.note) for r in results if not r.passed]
    assert not failed, failed
    assert len(results) >= 15
    assert any(r.category == "control" for r in results)