import sys

# Пикулин К. М. 2026

def ipv4_to_int(ip_str):
    #Преобразует IPv4 вида '192.168.1.1' в число
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
    #Преобразует IPv6 в 128-битное число (целое)
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
    #Определяет тип IP и пишет что это
    ip_str = ip_str.strip()
    
    # IPv4
    if '.' in ip_str:
        num = ipv4_to_int(ip_str)
        if num is not None:
            return (4, num, 32)
    
    # IPv6
    if ':' in ip_str:
        num = ipv6_to_int(ip_str)
        if num is not None:
            return (6, num, 128)
    
    return None

def find_common_mask(ip1, ip2):
    #Находит минимальную маску (в CIDR формате) между двумя IP
    parsed1 = validate_and_parse_ip(ip1)
    parsed2 = validate_and_parse_ip(ip2)
    
    if not parsed1:
        raise ValueError(f"Неверный IP-адрес: {ip1}")
    if not parsed2:
        raise ValueError(f"Неверный IP-адрес: {ip2}")
    
    ver1, num1, bits1 = parsed1
    ver2, num2, bits2 = parsed2
    
    if ver1 != ver2:
        raise ValueError(f"Разные версии IP: IPv{ver1} и IPv{ver2}")
    
    # Пошаговое сравнение битов
    mask_len = 0
    for i in range(bits1 - 1, -1, -1):
        bit1 = (num1 >> i) & 1
        bit2 = (num2 >> i) & 1
        if bit1 == bit2:
            mask_len += 1
        else:
            break
    
    return mask_len

def mask_to_dotted(mask_len):
    #Преобразует длину маски в точечную запись для IPv4
    if mask_len == 0:
        return "0.0.0.0"
    if mask_len == 32:
        return "255.255.255.255"
    mask_bits = (0xFFFFFFFF << (32 - mask_len)) & 0xFFFFFFFF
    return f"{(mask_bits >> 24) & 0xFF}.{(mask_bits >> 16) & 0xFF}.{(mask_bits >> 8) & 0xFF}.{mask_bits & 0xFF}"

def debug_ip_parts(ip_str, num, bits):
    #Отладка: показывает разбивку IP на части
    if bits == 32:
        # Для IPv4
        parts = []
        for i in range(3, -1, -1):
            part = (num >> (i * 8)) & 0xFF
            parts.append(str(part))
        print(f"  {ip_str} = {' '.join(parts)}")
        print(f"  HEX: {hex(num)}")
    else:
        # Для IPv6
        parts = []
        for i in range(7, -1, -1):
            part = (num >> (i * 16)) & 0xFFFF
            parts.append(f"{part:04x}")
        print(f"  {ip_str} = {' '.join(parts)}")
        print(f"  HEX: {hex(num)}")

def main():
    # Проверяем аргументы командной строки
    if len(sys.argv) != 3: # туториал
        print("Использование: python3 ip_finder.py <IP1> <IP2>")
        print("\nПримеры для IPv4:")
        print("  python3 ip_finder.py 192.168.1.1 192.168.1.100")
        print("  python3 ip_finder.py 192.168.1.1 192.168.2.1")
        print("  python3 ip_finder.py 10.0.0.1 10.0.0.1")
        print("  python3 ip_finder.py 8.9.1.1 8.10.1.1")
        print("\nПримеры для IPv6:")
        print("  python3 ip_finder.py 2001:db8::1 2001:db8::2")
        print("  python3 ip_finder.py 2001:db8:1234::1 2001:db8:1235::1")
        print("  python3 ip_finder.py 2001:db8:1234:5678::1 2001:db8:1234:5679::1")
        print("  python3 ip_finder.py fe80::1 fe80::2")
        sys.exit(1)
    
    ip1 = sys.argv[1]
    ip2 = sys.argv[2]
    
    try:   
        mask = find_common_mask(ip1, ip2)
        parsed = validate_and_parse_ip(ip1)
        ip_version = parsed[0] if parsed else None
        
        print("\n=== Результат ===")
        print(f"IP адрес 1: {ip1}")
        print(f"IP адрес 2: {ip2}")
        print(f"Версия IP: IPv{ip_version}")
        print(f"Минимальная общая маска: /{mask}")
        
        # Показываем маску в привычном формате для IPv4
        if ip_version == 4:
            dotted_mask = mask_to_dotted(mask)
            print(f"Маска в десятичном виде: {dotted_mask}")
            
            # Показываем общую сеть
            num = parsed[1]
            if mask == 32:
                network = num
            else:
                network = num & (0xFFFFFFFF << (32 - mask))
            network_ip = f"{(network >> 24) & 0xFF}.{(network >> 16) & 0xFF}.{(network >> 8) & 0xFF}.{network & 0xFF}"
            print(f"Общая сеть: {network_ip}/{mask}")
        
        print()
        
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()