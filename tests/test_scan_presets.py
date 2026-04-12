from guinmap.application.scan_presets import get_scan_preset, get_scan_presets
from guinmap.application.scan_profile_validator import ScanProfileValidator


def test_default_presets_generate_valid_profiles() -> None:
    validator = ScanProfileValidator()

    for preset in get_scan_presets():
        profile = preset.to_profile(targets=["scanme.nmap.org"])
        result = validator.validate(profile)

        assert result.is_valid is True, preset.key


def test_get_scan_preset_returns_expected_preset() -> None:
    preset = get_scan_preset("deep-assessment")

    assert preset is not None
    assert preset.label == "Deep assessment"
    assert preset.enable_os_detection is True
    assert preset.script_selection == ("default",)


def test_to_profile_returns_independent_mutable_lists() -> None:
    preset = get_scan_preset("balanced-tcp-inventory")

    assert preset is not None

    first_profile = preset.to_profile(targets=["127.0.0.1"])
    second_profile = preset.to_profile(targets=["192.168.1.10"])

    first_profile.extra_args.append("--open")

    assert "--open" not in second_profile.extra_args
    assert first_profile.targets == ["127.0.0.1"]
    assert second_profile.targets == ["192.168.1.10"]