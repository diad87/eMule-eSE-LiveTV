"""Negative fixtures for the same production registry checker; no file mutations."""
import contextlib
import copy
import io
import unittest
from unittest.mock import patch
import check_protocol_registry as checker

class RegistryTests(unittest.TestCase):
    def run_checker(self, rows, code):
        output=io.StringIO()
        with patch.object(checker,"load_registry",return_value=rows), patch.object(checker,"parse_code",return_value=code), contextlib.redirect_stdout(output):
            status=checker.main()
        return status,output.getvalue()
    def setUp(self):
        self.rows=checker.load_registry()
        self.code=checker.parse_code()
    def test_current_matches(self):
        self.assertEqual(self.run_checker(self.rows,self.code)[0],0)
    def test_string_collision(self):
        row=copy.deepcopy(next(r for r in self.rows if r["name"]=="kEseWirePeerAlpn"))
        row.update(name="kEseWireColliding",status="design")
        status,output=self.run_checker(self.rows+[row],self.code)
        self.assertEqual(status,1); self.assertIn("DUPLICATE VALUE",output)
    def test_string_drift(self):
        row=next(r for r in self.rows if r["name"]=="kEseWirePeerAlpn")
        row.update(value="ese-peer/2",_val="ese-peer/2")
        status,output=self.run_checker(self.rows,self.code)
        self.assertEqual(status,1); self.assertIn("DRIFT",output)
    def test_numeric_control_collision(self):
        row=copy.deepcopy(next(r for r in self.rows if r["name"]=="kEseWireControlHello"))
        row.update(name="kEseWireOtherControl",status="design")
        status,output=self.run_checker(self.rows+[row],self.code)
        self.assertEqual(status,1); self.assertIn("DUPLICATE VALUE",output)
    def test_numeric_control_drift(self):
        row=next(r for r in self.rows if r["name"]=="kEseWireControlAuth")
        row.update(value="11",_val=11)
        status,output=self.run_checker(self.rows,self.code)
        self.assertEqual(status,1); self.assertIn("DRIFT",output)
    def test_missing_symbol(self):
        del self.code["kEseWirePeerAlpn"]
        status,output=self.run_checker(self.rows,self.code)
        self.assertEqual(status,1); self.assertIn("NOT-IN-CODE",output)
    def test_unregistered_string(self):
        self.code["kEseWireUnregistered"]=("other/1","fixture",1)
        status,output=self.run_checker(self.rows,self.code)
        self.assertEqual(status,1); self.assertIn("UNREGISTERED",output)
    def test_magic_is_eight_bytes(self):
        self.assertEqual(self.code["kEseWireControlMagic"][0],"\x00ESECTL1")
        self.assertEqual(len(self.code["kEseWireControlMagic"][0]),8)
        self.assertEqual(checker.norm(r"\x00ESECTL1","string"),"\x00ESECTL1")
    def test_legacy_numeric_default(self):
        self.assertEqual(checker.norm("0xF0"),240)
        numeric=next(r for r in self.rows if r["name"]=="TAG_SOURCEIP_V6")
        self.assertEqual(numeric["_kind"],"number")
        self.assertEqual(numeric["_val"],0x66)
    def test_unknown_kind(self):
        with self.assertRaises(ValueError): checker.norm("1","unknown")
    def test_kad6_service_bits_are_governed_u64(self):
        for name, value in (("K6_CAP_DIRECT_INDEX_V1",1<<32),("K6_CAP_PEER_RDV_V1",1<<33)):
            self.assertTrue(checker.is_fork_symbol(name))
            self.assertEqual(self.code[name][0],value)
            row=next(r for r in self.rows if r["name"]==name)
            self.assertEqual(row["namespace"],"KAD6-SIGNED-CAP64")
            self.assertEqual(row["_val"],value)
    def test_kad6_service_collision_rejected(self):
        row=copy.deepcopy(next(r for r in self.rows if r["name"]=="K6_CAP_DIRECT_INDEX_V1"))
        row.update(name="K6_CAP_COLLIDING",status="design")
        status,output=self.run_checker(self.rows+[row],self.code)
        self.assertEqual(status,1); self.assertIn("DUPLICATE VALUE",output)
    def test_unregistered_kad6_service_rejected(self):
        self.code["K6_CAP_UNREGISTERED"]=(1<<34,"fixture",1)
        status,output=self.run_checker(self.rows,self.code)
        self.assertEqual(status,1); self.assertIn("UNREGISTERED",output)
if __name__=="__main__": unittest.main()
