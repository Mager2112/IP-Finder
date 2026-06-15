import sys

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
    #Преобразует IPv6 вида '2001:0db8::1' в 128-битное число
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
    #Определяет тип IP и возвращает (версия, число, битность)
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
    
    bits = bits1
        
    mask_len = 0
    for i in range(bits - 1, -1, -1):
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
    mask_bits = (0xFFFFFFFF << (32 - mask_len)) & 0xFFFFFFFF
    return f"{(mask_bits >> 24) & 0xFF}.{(mask_bits >> 16) & 0xFF}.{(mask_bits >> 8) & 0xFF}.{mask_bits & 0xFF}"

def main():
    # Проверяем аргументы командной строки
    if len(sys.argv) != 3:
        print("Использование: python3 ip_finder.py <IP1> <IP2>")
        print("Примеры:")
        print("  python3 ip_finder.py 192.168.1.1 192.168.1.100")
        print("  python3 ip_finder.py 2001:db8::1 2001:db8::2")
        print("  python3 ip_finder.py 10.0.0.1 192.168.1.1")
        sys.exit(1)
    
    ip1 = sys.argv[1]
    ip2 = sys.argv[2]
    
    try:
        mask = find_common_mask(ip1, ip2)
        parsed = validate_and_parse_ip(ip1)
        ip_version = parsed[0] if parsed else None
        
        print(f"IP адрес 1: {ip1}")
        print(f"IP адрес 2: {ip2}")
        print(f"Версия IP: IPv{ip_version}")
        print(f"Минимальная общая маска: /{mask}")
        
        # Показываем маску в привычном формате для IPv4
        if ip_version == 4:
            dotted_mask = mask_to_dotted(mask)
            print(f"Маска в десятичном виде: {dotted_mask}")
            
            # Дополнительно показываем сеть, которой принадлежат оба адреса
            num = parsed[1]
            network = num & (0xFFFFFFFF << (32 - mask))
            network_ip = f"{(network >> 24) & 0xFF}.{(network >> 16) & 0xFF}.{(network >> 8) & 0xFF}.{network & 0xFF}"
            print(f"Общая сеть: {network_ip}/{mask}")
        
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()