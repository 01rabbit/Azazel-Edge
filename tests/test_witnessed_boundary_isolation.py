"""SYNTHETIC external epochs only; actual FD identity/owned metadata stay fenced.

This reproduces one possible early-refusal mechanism. The historical CI failure's
cause remains UNKNOWN; no Source trial, old assessment or production code changes.
"""

import hashlib
import stat

import pytest

import test_witnessed_proofs as original
from test_witnessed_proofs import BoundaryRootOS, staged

PHASES = ["wrapper_enter", "original_return", "authenticated_prefix_assertion", "fault_injected"]


def scope(tmp_path, monkeypatch, *, isolated):
    external = tmp_path / "private-external-ancestor"
    external.mkdir(mode=0o755)
    owned = external / "owned"
    owned.mkdir(mode=0o755)
    bundle, proxy = staged(owned, monkeypatch, isolate_external=isolated)
    assert isinstance(proxy, BoundaryRootOS) is isolated
    return external, owned, bundle, proxy


def fingerprints(bundle, *, relocated_from=None, relocated_to=None):
    result = {}
    for name, path in bundle["paths"].items():
        if relocated_from is not None:
            path = relocated_to / path.relative_to(relocated_from)
        if path.exists():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def exception_chain(exc):
    result, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        result.append((type(exc).__name__, str(exc)))
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    return result


def assert_closed(proxy):
    assert proxy.opened and sorted(proxy.opened) == sorted(proxy.closed)


def after_first_read(proxy, action):
    """A deterministic action after real reads, before the original held fence."""
    real_read, actions = proxy.read, []
    def read(fd, maximum):
        raw = real_read(fd, maximum)
        if raw and not actions:
            action()
            actions.append(True)
        return raw
    proxy.read = read
    return actions


def ambient_drift(external):
    # Leave both entries present: directory nlink and real epochs actually change.
    (external / "unrelated-directory").mkdir()
    (external / "unrelated-file").write_bytes(b"SYNTHETIC unrelated directory churn")


def witness_phase_hook(monkeypatch, bundle, proxy, *, fault):
    real_witness, phases, changed = original.p._witness, [], []
    if fault == "boot":
        monkeypatch.setattr(original.p.collection, "_kernel_boot_id",
            lambda: "00000000-0000-4000-8000-000000000002" if changed else bundle["scope"]["kernel_boot_id"])
    def witness(*args, **kwargs):
        phases.append("wrapper_enter")
        result = real_witness(*args, **kwargs)
        phases.append("original_return")
        assert result["witness_prefix_authenticated"] is True
        phases.append("authenticated_prefix_assertion")
        if fault == "uid":
            proxy.case = "wrong-reader"
        elif fault == "mutation":
            anchors = bundle["paths"]["anchors"]
            anchors.chmod(0o644)
            anchors.write_bytes(anchors.read_bytes() + b" ")
            anchors.chmod(0o444)
        changed.append(True)
        phases.append("fault_injected")
        return result
    monkeypatch.setattr(original.p, "_witness", witness)
    return phases, changed


def test_unisolated_ambient_drift_refuses_before_witness_with_cause_and_all_fds_closed(tmp_path, monkeypatch):
    external, owned, bundle, proxy = scope(tmp_path, monkeypatch, isolated=False)
    before = fingerprints(bundle)
    phases, changed = witness_phase_hook(monkeypatch, bundle, proxy, fault="uid")
    actions = after_first_read(proxy, lambda: ambient_drift(external))
    with pytest.raises(original.p.collection.SafetyCollectionError) as caught:
        original.collect(bundle)
    assert actions == [True] and phases == [] and changed == []
    chain = exception_chain(caught.value)
    assert any(message == "artifact or ancestor metadata changed" for _, message in chain)
    assert not any("witness reader changed" in message for _, message in chain)
    assert fingerprints(bundle) == before
    assert_closed(proxy)
    assert owned.exists()


def test_isolated_no_fault_preserves_exact_old_result_and_unqualified_witness(tmp_path, monkeypatch):
    external, owned, bundle, proxy = scope(tmp_path, monkeypatch, isolated=True)
    before = fingerprints(bundle)
    base = original.p.proofs.collect_safety_proofs(bundle["paths"]["enrollment"], bundle["paths"]["supplement"],
        **{key: bundle[key] for key in ("expected_enrollment_sha256", "expected_checkpoint_sha256", "expected_supplement_sha256")})
    result = original.collect(bundle)
    assert original._json(result["base_collection"]) == original._json(base)
    assert result["source_witness"]["witness_prefix_authenticated"] is True
    assert result["source_witness"]["journal_verified"] is False and result["qualified_safety_count"] is None
    assert not any(result["authority_flags"].values())
    assert fingerprints(bundle) == before
    assert proxy.owned_root == owned
    assert proxy.external_epochs
    assert all(stat.S_ISDIR(mode) for mode in proxy.external_modes.values())
    assert external.exists()
    assert_closed(proxy)


@pytest.mark.parametrize("fault", ["mutation", "uid", "boot"])
def test_isolated_same_ambient_drift_reaches_exact_post_witness_fault(tmp_path, monkeypatch, fault):
    external, _, bundle, proxy = scope(tmp_path, monkeypatch, isolated=True)
    before = fingerprints(bundle)
    phases, changed = witness_phase_hook(monkeypatch, bundle, proxy, fault=fault)
    actions = after_first_read(proxy, lambda: ambient_drift(external))
    with pytest.raises(original.p.collection.SafetyCollectionError) as caught:
        original.collect(bundle)
    assert actions == [True] and phases == PHASES and changed == [True]
    messages = [message for _, message in exception_chain(caught.value)]
    if fault in ("uid", "boot"):
        assert "witness reader changed" in messages
        assert not any("artifact or ancestor metadata changed" in message for message in messages)
        assert fingerprints(bundle) == before
    else:
        assert "artifact or ancestor metadata changed" in messages
        assert not any("witness reader changed" in message for message in messages)
        after = fingerprints(bundle)
        assert after["anchors"] != before["anchors"]
        assert {key: value for key, value in after.items() if key != "anchors"} == {key: value for key, value in before.items() if key != "anchors"}
    assert_closed(proxy)


@pytest.mark.parametrize("fault", ["inode_replacement", "type_replacement", "raw_group_write_added"])
def test_external_real_identity_type_and_raw_mode_changes_are_never_stabilized(tmp_path, monkeypatch, fault):
    external, _, bundle, proxy = scope(tmp_path, monkeypatch, isolated=True)
    before = fingerprints(bundle)
    phases, changed = witness_phase_hook(monkeypatch, bundle, proxy, fault="uid")
    retained = tmp_path / "retained-original-ancestor"
    original_inode = external.stat().st_ino
    def mutate():
        if fault == "raw_group_write_added":
            external.chmod(stat.S_IMODE(external.stat().st_mode) | 0o020)
        else:
            external.rename(retained)
            if fault == "inode_replacement":
                external.mkdir(mode=0o755)
                assert external.stat().st_ino != original_inode
            else:
                external.write_bytes(b"SYNTHETIC replacement is a regular file")
                assert external.is_file()
    actions = after_first_read(proxy, mutate)
    with pytest.raises(original.p.collection.SafetyCollectionError) as caught:
        original.collect(bundle)
    assert actions == [True] and phases == [] and changed == []
    messages = [message for _, message in exception_chain(caught.value)]
    if fault == "raw_group_write_added":
        assert any("synthetic external ancestor raw mode changed" in message for message in messages)
        assert fingerprints(bundle) == before
    else:
        assert any("artifact or ancestor metadata changed" in message or "unsafe Root ancestor" in message for message in messages)
        assert fingerprints(bundle, relocated_from=external, relocated_to=retained) == before
    assert_closed(proxy)


@pytest.mark.parametrize("fault", ["owned_directory_epoch", "enrolled_file_metadata", "owned_group_write", "owned_world_write"])
def test_owned_directory_and_enrolled_file_metadata_remain_real(tmp_path, monkeypatch, fault):
    _, owned, bundle, proxy = scope(tmp_path, monkeypatch, isolated=True)
    before = fingerprints(bundle)
    phases, changed = witness_phase_hook(monkeypatch, bundle, proxy, fault="uid")
    def mutate():
        if fault == "owned_directory_epoch":
            # The ENTIRE supplied owned root is real, including outside sealed/.
            (owned / "unrelated-but-owned-directory").mkdir()
        elif fault == "enrolled_file_metadata":
            bundle["paths"]["observations"].chmod(0o644)
        else:
            owned.chmod(stat.S_IMODE(owned.stat().st_mode) | (0o020 if fault == "owned_group_write" else 0o002))
    actions = after_first_read(proxy, mutate)
    with pytest.raises(original.p.collection.SafetyCollectionError) as caught:
        original.collect(bundle)
    assert actions == [True] and phases == [] and changed == []
    messages = [message for _, message in exception_chain(caught.value)]
    if fault in ("owned_group_write", "owned_world_write"):
        assert "unsafe Root ancestor" in messages  # Raw owned mode, not just a ctime side effect.
    else:
        assert any("artifact or ancestor metadata changed" in message or "unsafe or oversized enrolled artifact" in message for message in messages)
    assert fingerprints(bundle) == before
    assert_closed(proxy)
