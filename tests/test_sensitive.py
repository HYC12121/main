import pytest
from backend.app.scanners.sensitive_inspector import SensitiveInspector

def test_id_card_checksum_validation():
    # 正确合法的 18 位身份证 (校验位计算匹配)
    valid_id_1 = "110101199003072340"
    valid_id_2 = "330102198506152011"
    assert SensitiveInspector.validate_id_card(valid_id_1) is True
    assert SensitiveInspector.validate_id_card(valid_id_2) is True
    
    # 随机篡改最后一位的非法身份证 (过滤误报)
    invalid_id = "110101199003072349"
    assert SensitiveInspector.validate_id_card(invalid_id) is False

def test_luhn_bank_card_validation():
    # 真实 Luhn 合法卡号
    valid_card = "6222021234567890128"
    assert SensitiveInspector.validate_luhn(valid_card) is True
    
    # 篡改最后一位非法卡号
    invalid_card = "6222021234567890124"
    assert SensitiveInspector.validate_luhn(invalid_card) is False

def test_sensitive_data_masking():
    id_card = "110101199003072345"
    masked_id = SensitiveInspector.mask_sensitive_value(id_card, "ID_CARD")
    assert masked_id == "110101********2345"
    
    phone = "13812345678"
    masked_phone = SensitiveInspector.mask_sensitive_value(phone, "PHONE")
    assert masked_phone == "138****5678"
    
    ak = "LTAI4G1234567890abcdef"
    masked_ak = SensitiveInspector.mask_sensitive_value(ak, "SECRET_KEY")
    assert masked_ak.startswith("LTAI") and masked_ak.endswith("cdef")
