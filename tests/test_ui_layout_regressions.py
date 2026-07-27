#!/usr/bin/env python3
"""Regression guards for the beta splash screen and Connection preferences."""

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SPLASH_SOURCE = REPO_ROOT / "srchybrid" / "SplashScreen.cpp"
RESOURCE_SOURCE = REPO_ROOT / "srchybrid" / "emule.rc"


def dialog_block(resource_text: str, dialog_id: str) -> str:
    match = re.search(
        rf"^{re.escape(dialog_id)}\s+DIALOGEX\b(?P<body>.*?^END\s*$)",
        resource_text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"dialog {dialog_id} was not found")
    return match.group("body")


def control_rect(dialog: str, control_id: str) -> tuple[int, int, int, int]:
    match = re.search(
        rf"^[^\r\n]*\b{re.escape(control_id)}\b[^\r\n]*,"
        rf"(\d+),(\d+),(\d+),(\d+)\s*$",
        dialog,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"control {control_id} was not found")
    return tuple(map(int, match.groups()))


def overlaps(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    return ax < bx + bw and bx < ax + aw and ay < by + bh and by < ay + ah


class UiLayoutRegressions(unittest.TestCase):
    def test_splash_version_is_fitted_to_the_bitmap(self) -> None:
        source = SPLASH_SOURCE.read_text(encoding="utf-8-sig")
        self.assertIn("iMaxTextWidth", source)
        self.assertIn("dc.GetTextExtent(strAppVersion).cx <= iMaxTextWidth", source)
        self.assertRegex(source, r"for \(int iHeight = lf\.lfHeight; iHeight >= 16; --iHeight\)")
        self.assertIn("DT_SINGLELINE", source)

    def test_ipv6_control_is_inside_network_group_without_overlap(self) -> None:
        resource = RESOURCE_SOURCE.read_text(encoding="utf-8-sig")
        connection = dialog_block(resource, "IDD_PPG_CONNECTION")

        ipv6 = control_rect(connection, "IDC_PREF_ENABLE_IPV6")
        network = control_rect(connection, "IDC_CONNECTION_NETWORK")
        network_x, network_y, network_w, network_h = network
        ipv6_x, ipv6_y, ipv6_w, ipv6_h = ipv6

        self.assertGreaterEqual(ipv6_x, network_x)
        self.assertGreaterEqual(ipv6_y, network_y)
        self.assertLessEqual(ipv6_x + ipv6_w, network_x + network_w)
        self.assertLessEqual(ipv6_y + ipv6_h, network_y + network_h)

        for control_id in (
            "IDC_MAXSRC_FRM",
            "IDC_MAXCONN_FRM",
            "IDC_AUTOCONNECT",
            "IDC_RECONN",
            "IDC_SHOWOVERHEAD",
            "IDC_WIZARD",
        ):
            with self.subTest(control=control_id):
                self.assertFalse(overlaps(ipv6, control_rect(connection, control_id)))

        self.assertNotIn("IDC_PREF_IPV6_HINT", connection)


if __name__ == "__main__":
    unittest.main()
