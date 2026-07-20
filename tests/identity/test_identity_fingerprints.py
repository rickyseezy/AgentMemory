"""ID-001 keyed fingerprint and remote-normalization tests."""

from __future__ import annotations

import pytest

from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter
from agentmemory.identity.domain.errors import IdentityValidationError
from agentmemory.identity.domain.services import normalize_git_remote
from agentmemory.identity.domain.value_objects import StableId, VcsType

DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        (
            "https://user:secret@Example.COM:443/Org/Repo.git?token=secret#fragment",
            "https://example.com/Org/Repo",
        ),
        ("ssh://git@Example.COM:22/Org/Repo.git", "ssh://example.com/Org/Repo"),
        ("git+ssh://git@Example.COM/Org/Repo/", "ssh://example.com/Org/Repo"),
        ("git@Example.COM:Org/Repo.git", "ssh://example.com/Org/Repo"),
        ("Example.COM:Org/Repo.git", "ssh://example.com/Org/Repo"),
        ("http://Example.COM:80/Org/Repo.git", "http://example.com/Org/Repo"),
        ("https://Example.COM:8443/Org/Repo.git", "https://example.com:8443/Org/Repo"),
    ],
)
def test_remote_normalization_removes_credentials_and_transport_noise(
    remote: str,
    expected: str,
) -> None:
    normalized = normalize_git_remote(remote)
    assert normalized == expected
    assert "secret" not in normalized
    assert "user" not in normalized
    assert "git@" not in normalized


@pytest.mark.parametrize(
    "remote",
    [
        "",
        "file:///tmp/repo",
        "https:///missing-host",
        "C:\\repo",
        "ssh://host",
        "ssh://host/.hidden",
        "ssh://host/org//repo",
        "ssh://host/org\\repo",
    ],
)
def test_remote_normalization_rejects_local_or_ambiguous_identifiers(remote: str) -> None:
    with pytest.raises(IdentityValidationError):
        normalize_git_remote(remote)


def test_repository_fingerprint_is_order_stable_and_every_identity_delta_changes_it() -> None:
    fingerprinter = IdentityFingerprinter(b"i" * 32)
    baseline = fingerprinter.repository(
        VcsType.GIT,
        "sha1",
        ("b" * 40, "a" * 40),
        REPOSITORY_ID,
        "https://example.com/Org/Repo",
    )
    assert baseline == fingerprinter.repository(
        VcsType.GIT,
        "sha1",
        ("a" * 40, "b" * 40),
        REPOSITORY_ID,
        "https://example.com/Org/Repo",
    )
    changes = (
        fingerprinter.repository(
            VcsType.GIT,
            "sha256",
            ("a" * 64, "b" * 64),
            REPOSITORY_ID,
            "https://example.com/Org/Repo",
        ),
        fingerprinter.repository(
            VcsType.GIT,
            "sha1",
            ("a" * 40,),
            REPOSITORY_ID,
            "https://example.com/Org/Repo",
        ),
        fingerprinter.repository(
            VcsType.GIT,
            "sha1",
            ("a" * 40, "b" * 40),
            None,
            "https://example.com/Org/Repo",
        ),
        fingerprinter.repository(
            VcsType.GIT,
            "sha1",
            ("a" * 40, "b" * 40),
            REPOSITORY_ID,
            "https://example.com/Org/Fork",
        ),
    )
    assert all(value != baseline for value in changes)


def test_path_is_location_evidence_and_never_the_repository_fingerprint() -> None:
    fingerprinter = IdentityFingerprinter(b"i" * 32)
    repository = fingerprinter.repository(
        VcsType.GIT,
        "sha1",
        ("a" * 40,),
        None,
        "https://example.com/Org/Repo",
    )
    first_path = fingerprinter.path(DEVICE_ID, "volume-a", "/work/original")
    moved_path = fingerprinter.path(DEVICE_ID, "volume-a", "/work/moved")
    assert first_path != moved_path
    assert repository not in {first_path, moved_path}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (r"C:\\Users\\Ricky\\Project", r"c:\\users\\ricky\\project"),
        (r"\\\\server\\share\\Project", r"/mnt/share/Project"),
        (r"C:\\work\\Project", r"/mnt/c/work/Project"),
    ],
)
def test_windows_wsl_and_case_variants_remain_distinct_location_observations(
    first: str,
    second: str,
) -> None:
    fingerprinter = IdentityFingerprinter(b"i" * 32)
    assert fingerprinter.path(DEVICE_ID, "volume", first) != fingerprinter.path(
        DEVICE_ID,
        "volume",
        second,
    )


def test_identity_index_key_must_have_256_bits() -> None:
    with pytest.raises(IdentityValidationError, match="256 bits"):
        IdentityFingerprinter(b"short")


@pytest.mark.parametrize(
    ("object_format", "roots"),
    [
        ("md5", ("a" * 40,)),
        ("sha1", ()),
        ("sha1", ("g" * 40,)),
        ("sha256", ("a" * 40,)),
    ],
)
def test_repository_fingerprint_rejects_incomplete_or_malformed_roots(
    object_format: str,
    roots: tuple[str, ...],
) -> None:
    with pytest.raises(IdentityValidationError, match="root identity"):
        IdentityFingerprinter(b"i" * 32).repository(
            VcsType.GIT,
            object_format,
            roots,
            None,
            None,
        )


@pytest.mark.parametrize(("volume", "path"), [("", "/work"), ("volume", "")])
def test_path_fingerprint_requires_complete_location_evidence(volume: str, path: str) -> None:
    with pytest.raises(IdentityValidationError, match="path identity"):
        IdentityFingerprinter(b"i" * 32).path(DEVICE_ID, volume, path)


def test_opaque_fingerprint_requires_an_algorithm_and_value() -> None:
    fingerprinter = IdentityFingerprinter(b"i" * 32)
    with pytest.raises(IdentityValidationError, match="opaque identity"):
        fingerprinter.opaque("", "value")
    with pytest.raises(IdentityValidationError, match="opaque identity"):
        fingerprinter.opaque("AlgorithmV1", "")
