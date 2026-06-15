def ipv4_to_int(ip_str):
    """Преобразует IPv4 вида '192.168.1.1' в число"""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return None
    result = 0
    for part in parts:
        if not part.isdigit():
            return None
        num = int(part)
        if num < 0 or num > 255:
            return None
        result = (result << 8) | num
    return result

def ipv6_to_int(ip_str):
    """Преобразует IPv6 вида '2001:0db8::1' в 128-битное число"""
    # Обработка сжатия ::
    if '::' in ip_str:
        left, right = ip_str.split('::', 1)
        left_parts = left.split(':') if left else []
        right_parts = right.split(':') if right else []
        missing = 8 - len(left_parts) - len(right_parts)
        parts = left_parts + ['0'] * missing + right_parts
    else:
        parts = ip_str.split(':')
    
    if len(parts) != 8:
        return None
    
    result = 0
    for part in parts:
        if part == '':
            return None
        if not all(c in '0123456789abcdefABCDEF' for c in part):
            return None
        if len(part) > 4:
            return None
        num = int(part, 16)
        result = (result << 16) | num
    return result

def validate_and_parse_ip(ip_str):
    """Определяет тип IP и возвращает (версия, число, битность)"""
    ip_str = ip_str.strip()
    
    # Попробуем IPv4
    if '.' in ip_str and ':' not in ip_str:
        num = ipv4_to_int(ip_str)
        if num is not None:
            return (4, num, 32)
    
    # Попробуем IPv6
    if ':' in ip_str:
        num = ipv6_to_int(ip_str)
        if num is not None:
            return (6, num, 128)
    
    return None

def find_common_mask(ip1, ip2):
    """Находит минимальную маску (в CIDR формате) между двумя IP"""
    parsed1 = validate_and_parse_ip(ip1)
    parsed2 = validate_and_parse_ip(ip2)
    
    if not parsed1:
        raise ValueError(f"Неверный IP-адрес: {ip1}")
    if not parsed2:
        raise ValueError(f"Неверный IP-адрес: {ip2}")
    
    ver1, num1, bits1 = parsed1
    ver2, num2, bits2 = parsed2
    
    if ver1 != ver2:
        raise ValueError(f"Разные версии IP: {ver1} и {ver2}")
    
    bits = bits1
    # Находим позицию первого отличающегося бита
    diff_pos = bits - 1
    while diff_pos >= 0:
        bit1 = (num1 >> diff_pos) & 1
        bit2 = (num2 >> diff_pos) & 1
        if bit1 != bit2:
            break
        diff_pos -= 1
    
    # Маска = количество совпадающих битов
    mask_len = diff_pos  # т.к. diff_pos указывает на последний совпавший бит
    
    return mask_len

def format_mask(ip_version, mask_len):
    """Форматирует маску для вывода"""
    if ip_version == 4:
        return f"/{mask_len}"
    else:
        return f"/{mask_len}"

# Пример использования
if __name__ == "__main__":
    test_cases = [
        ("192.168.1.1", "192.168.1.100"),
        ("192.168.1.1", "192.168.2.1"),
        ("10.0.0.1", "10.0.0.1"),
        ("192.168.1.1", "8.8.8.8"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7335"),
        ("2001:db8::1", "2001:db8::2"),
        ("fe80::1", "ff00::1"),
    ]
    
    for ip1, ip2 in test_cases:
        try:
            mask = find_common_mask(ip1, ip2)
            ver = validate_and_parse_ip(ip1)[0]
            print(f"{ip1} и {ip2} -> общая маска: /{mask}")
        except Exception as e:
            print(f"Ошибка: {e} для {ip1} и {ip2}")