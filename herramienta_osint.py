import os
import requests
import json
import webbrowser
from datetime import datetime
import socket
import whois
from PIL import Image
import exifread
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import dns.resolver
import shodan
import ipwhois
from pyfiglet import Figlet
from termcolor import colored
import inquirer

# Configuración de API keys (debes obtener las tuyas propias)
SHODAN_API_KEY = 'TU_API_KEY_DE_SHODAN'
VIRUSTOTAL_API_KEY = 'TU_API_KEY_DE_VIRUSTOTAL'
HUNTER_API_KEY = 'TU_API_KEY_DE_HUNTER'

# Variables de idioma
LANG = {
    'es': {
        'title': "HERRAMIENTA OSINT",
        'author': "Hecho por bochisline",
        'contact': "Contacto: Discord: bochisline | Instagram: @bochisline",
        'select_lang': "Selecciona tu idioma:",
        'menu_options': [
            "Buscar usuario en redes sociales",
            "Analizar número telefónico",
            "Analizar correo electrónico",
            "Analizar dirección IP",
            "Analizar imagen (metadatos)",
            "Salir"
        ],
        'enter_option': "Seleccione una opción (1-6): ",
        'enter_username': "Ingrese el nombre de usuario a buscar: ",
        'phone_prompt': "Ingrese el número telefónico (con código de país): ",
        'email_prompt': "Ingrese el correo electrónico: ",
        'ip_prompt': "Ingrese la dirección IP: ",
        'image_prompt': "Ingrese la ruta de la imagen: ",
        'invalid_option': "Opción no válida. Intente nuevamente.",
        'press_enter': "Presione Enter para continuar...",
        'exiting': "Saliendo del programa...",
        'user_search': "Buscando usuario: {} en redes sociales...",
        'found_accounts': "Resumen de cuentas encontradas:",
        'no_accounts': "No se encontraron cuentas con ese nombre de usuario",
        'phone_analysis': "Analizando número telefónico: {}",
        'email_analysis': "Analizando correo electrónico: {}",
        'ip_analysis': "Analizando dirección IP: {}",
        'image_analysis': "Analizando imagen: {}",
        'invalid_input': "Debe ingresar un valor válido"
    },
    'en': {
        'title': "OSINT TOOL",
        'author': "Created by bochisline",
        'contact': "Contact: Discord: bochisline | Instagram: @bochisline",
        'select_lang': "Select your language:",
        'menu_options': [
            "Search username on social networks",
            "Analyze phone number",
            "Analyze email address",
            "Analyze IP address",
            "Analyze image (metadata)",
            "Exit"
        ],
        'enter_option': "Select an option (1-6): ",
        'enter_username': "Enter username to search: ",
        'phone_prompt': "Enter phone number (with country code): ",
        'email_prompt': "Enter email address: ",
        'ip_prompt': "Enter IP address: ",
        'image_prompt': "Enter image path: ",
        'invalid_option': "Invalid option. Try again.",
        'press_enter': "Press Enter to continue...",
        'exiting': "Exiting program...",
        'user_search': "Searching username: {} on social networks...",
        'found_accounts': "Summary of found accounts:",
        'no_accounts': "No accounts found with that username",
        'phone_analysis': "Analyzing phone number: {}",
        'email_analysis': "Analyzing email address: {}",
        'ip_analysis': "Analyzing IP address: {}",
        'image_analysis': "Analyzing image: {}",
        'invalid_input': "You must enter a valid value"
    },
    'pt': {
        'title': "FERRAMENTA OSINT",
        'author': "Feito por bochisline",
        'contact': "Contato: Discord: bochisline | Instagram: @bochisline",
        'select_lang': "Selecione seu idioma:",
        'menu_options': [
            "Buscar usuário em redes sociais",
            "Analisar número de telefone",
            "Analisar endereço de email",
            "Analisar endereço IP",
            "Analisar imagem (metadados)",
            "Sair"
        ],
        'enter_option': "Selecione uma opção (1-6): ",
        'enter_username': "Digite o nome de usuário para buscar: ",
        'phone_prompt': "Digite o número de telefone (com código do país): ",
        'email_prompt': "Digite o endereço de email: ",
        'ip_prompt': "Digite o endereço IP: ",
        'image_prompt': "Digite o caminho da imagem: ",
        'invalid_option': "Opção inválida. Tente novamente.",
        'press_enter': "Pressione Enter para continuar...",
        'exiting': "Saindo do programa...",
        'user_search': "Buscando usuário: {} em redes sociais...",
        'found_accounts': "Resumo de contas encontradas:",
        'no_accounts': "Nenhuma conta encontrada com esse nome de usuário",
        'phone_analysis': "Analisando número de telefone: {}",
        'email_analysis': "Analisando endereço de email: {}",
        'ip_analysis': "Analisando endereço IP: {}",
        'image_analysis': "Analisando imagem: {}",
        'invalid_input': "Você deve inserir um valor válido"
    }
}

current_lang = 'es'  # Idioma por defecto

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    f = Figlet(font='slant')
    banner = f.renderText('OSINT TOOL')
    print(colored(banner, 'cyan'))
    print(colored("="*60, 'blue'))
    print(colored(LANG[current_lang]['title'].center(60), 'green'))
    print(colored(LANG[current_lang]['author'].center(60), 'yellow'))
    print(colored(LANG[current_lang]['contact'].center(60), 'magenta'))
    print(colored("="*60, 'blue'))
    print("\n")

def select_language():
    clear_screen()
    questions = [
        inquirer.List('language',
                      message=colored("Select your language / Selecciona tu idioma / Selecione seu idioma:", 'yellow'),
                      choices=[
                          ('Español', 'es'),
                          ('English', 'en'),
                          ('Português', 'pt')
                      ],
        )
    ]
    answers = inquirer.prompt(questions)
    return answers['language']

def username_search(username):
    print(colored(LANG[current_lang]['user_search'].format(username), 'yellow'))
    
    social_networks = {
        'Facebook': f'https://www.facebook.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}',
        'LinkedIn': f'https://www.linkedin.com/in/{username}',
        'YouTube': f'https://www.youtube.com/user/{username}',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'Pinterest': f'https://www.pinterest.com/{username}',
        'Tumblr': f'https://{username}.tumblr.com',
        'Flickr': f'https://www.flickr.com/people/{username}',
        'Vimeo': f'https://vimeo.com/{username}',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'Github': f'https://github.com/{username}',
        'GitLab': f'https://gitlab.com/{username}',
        'Bitbucket': f'https://bitbucket.org/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Dev.to': f'https://dev.to/{username}',
        'Twitch': f'https://www.twitch.tv/{username}',
        'Steam': f'https://steamcommunity.com/id/{username}',
        'TikTok': f'https://www.tiktok.com/@{username}',
        'Snapchat': f'https://www.snapchat.com/add/{username}',
        'Telegram': f'https://t.me/{username}',
        'VK': f'https://vk.com/{username}',
        'Quora': f'https://www.quora.com/profile/{username}'
    }
    
    found_accounts = []
    
    for site, url in social_networks.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(colored(f"[+] {site}: Found - {url}", 'green'))
                found_accounts.append((site, url))
            else:
                print(colored(f"[-] {site}: Not found", 'red'))
        except requests.RequestException:
            print(colored(f"[-] {site}: Connection error", 'red'))
    
    return found_accounts

def phone_number_info(phone_number):
    print(colored(LANG[current_lang]['phone_analysis'].format(phone_number), 'yellow'))
    
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            print(colored("[-] Invalid phone number", 'red'))
            return
        
        print(colored("\n[+] Phone number information:", 'green'))
        print(f"Country: {geocoder.description_for_number(parsed_number, 'en')}")
        print(f"Carrier: {carrier.name_for_number(parsed_number, 'en')}")
        print(f"Timezone: {timezone.time_zones_for_number(parsed_number)}")
        print(f"International format: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"E164 format: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)}")
        
        print(colored("\n[+] Searching public directories...", 'yellow'))
        print("Note: For detailed searches, consider using a Truecaller API")
        
    except Exception as e:
        print(colored(f"[-] Error analyzing number: {str(e)}", 'red'))

def email_search(email):
    print(colored(LANG[current_lang]['email_analysis'].format(email), 'yellow'))
    
    if '@' not in email or '.' not in email.split('@')[-1]:
        print(colored("[-] Invalid email address", 'red'))
        return
    
    print(colored("\n[+] Checking data breaches...", 'yellow'))
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": "TU_API_KEY_DE_HIBP"}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            breaches = json.loads(response.text)
            print(colored(f"[!] This email appears in {len(breaches)} data breaches:", 'red'))
            for breach in breaches:
                print(f"- {breach['Name']} ({breach['BreachDate']})")
        elif response.status_code == 404:
            print(colored("[+] No breaches found for this email", 'green'))
        else:
            print(colored("[-] Error querying Have I Been Pwned", 'red'))
    except:
        print(colored("[-] Could not check breaches (API unavailable)", 'red'))
    
    if HUNTER_API_KEY:
        print(colored("\n[+] Searching with Hunter.io...", 'yellow'))
        try:
            url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}"
            response = requests.get(url)
            data = json.loads(response.text)
            
            if data.get('data'):
                info = data['data']
                print(f"Status: {info['status']}")
                print(f"Result: {info['result']}")
                print(f"Quality: {info['score']}%")
                print(f"Possible name: {info.get('first_name', 'Unknown')} {info.get('last_name', '')}")
                print(f"Public sources: {info.get('sources', [])}")
            else:
                print(colored("[-] No additional information found", 'red'))
        except:
            print(colored("[-] Error querying Hunter.io", 'red'))
    else:
        print(colored("[-] Hunter.io API key not configured", 'yellow'))

def ip_info(ip_address):
    print(colored(LANG[current_lang]['ip_analysis'].format(ip_address), 'yellow'))
    
    try:
        print(colored("\n[+] Basic information:", 'green'))
        try:
            ipwhois_result = ipwhois.IPWhois(ip_address).lookup_rdap()
            print(f"ASN: {ipwhois_result.get('asn', 'Unknown')}")
            print(f"ASN Description: {ipwhois_result.get('asn_description', 'Unknown')}")
            print(f"Country: {ipwhois_result.get('asn_country_code', 'Unknown')}")
            print(f"Registry: {ipwhois_result.get('network', {}).get('name', 'Unknown')}")
        except:
            print(colored("[-] Could not get WHOIS information", 'red'))
        
        print(colored("\n[+] Approximate geolocation:", 'green'))
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            data = json.loads(response.text)
            if data['status'] == 'success':
                print(f"Country: {data['country']} ({data['countryCode']})")
                print(f"Region: {data['regionName']} ({data['region']})")
                print(f"City: {data['city']}")
                print(f"Postal code: {data['zip']}")
                print(f"Coordinates: Lat {data['lat']}, Lon {data['lon']}")
                print(f"Timezone: {data['timezone']}")
                print(f"ISP: {data['isp']}")
                print(f"Organization: {data['org']}")
                print(f"AS: {data['as']}")
            else:
                print(colored("[-] Could not get geolocation", 'red'))
        except:
            print(colored("[-] Error getting geolocation", 'red'))
        
        if SHODAN_API_KEY:
            print(colored("\n[+] Searching Shodan...", 'yellow'))
            try:
                api = shodan.Shodan(SHODAN_API_KEY)
                results = api.host(ip_address)
                
                print(f"Open ports: {', '.join(str(port) for port in results['ports'])}")
                if 'vulns' in results:
                    print(f"Vulnerabilities: {', '.join(results['vulns'])}")
                if 'domains' in results:
                    print(f"Associated domains: {', '.join(results['domains'])}")
                if 'hostnames' in results:
                    print(f"Hostnames: {', '.join(results['hostnames'])}")
                if 'os' in results:
                    print(f"Operating system: {results['os']}")
            except shodan.APIError as e:
                print(colored(f"[-] Shodan error: {str(e)}", 'red'))
            except:
                print(colored("[-] Error querying Shodan", 'red'))
        else:
            print(colored("[-] Shodan API key not configured", 'yellow'))
        
    except Exception as e:
        print(colored(f"[-] Error analyzing IP: {str(e)}", 'red'))

def analyze_image(image_path):
    print(colored(LANG[current_lang]['image_analysis'].format(image_path), 'yellow'))
    
    try:
        with Image.open(image_path) as img:
            print(colored("\n[+] Basic information:", 'green'))
            print(f"Format: {img.format}")
            print(f"Mode: {img.mode}")
            print(f"Size: {img.size[0]}x{img.size[1]} pixels")
            
            print(colored("\n[+] EXIF metadata:", 'green'))
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f)
                if tags:
                    for tag, value in tags.items():
                        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                            print(f"{tag}: {value}")
                else:
                    print(colored("[-] No EXIF metadata found", 'red'))
                    
            print(colored("\n[+] You can perform a reverse image search at:", 'yellow'))
            print(f"https://images.google.com/searchbyimage?image_url={os.path.abspath(image_path)}")
            
    except Exception as e:
        print(colored(f"[-] Error analyzing image: {str(e)}", 'red'))

def main_menu():
    global current_lang
    current_lang = select_language()
    
    while True:
        print_banner()
        print(colored(LANG[current_lang]['menu_options'][0], 'cyan') + " (1)")
        print(colored(LANG[current_lang]['menu_options'][1], 'cyan') + " (2)")
        print(colored(LANG[current_lang]['menu_options'][2], 'cyan') + " (3)")
        print(colored(LANG[current_lang]['menu_options'][3], 'cyan') + " (4)")
        print(colored(LANG[current_lang]['menu_options'][4], 'cyan') + " (5)")
        print(colored(LANG[current_lang]['menu_options'][5], 'red') + " (6)")
        print(colored("="*60, 'blue'))
        
        choice = input("\n" + colored(LANG[current_lang]['enter_option'], 'yellow'))
        
        if choice == '1':
            username = input("\n" + colored(LANG[current_lang]['enter_username'], 'yellow')).strip()
            if username:
                found = username_search(username)
                if found:
                    print("\n" + colored(LANG[current_lang]['found_accounts'], 'green'))
                    for site, url in found:
                        print(colored(f"- {site}: {url}", 'green'))
                else:
                    print("\n" + colored(LANG[current_lang]['no_accounts'], 'red'))
            else:
                print("\n" + colored(LANG[current_lang]['invalid_input'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))
            
        elif choice == '2':
            phone = input("\n" + colored(LANG[current_lang]['phone_prompt'], 'yellow')).strip()
            if phone:
                phone_number_info(phone)
            else:
                print("\n" + colored(LANG[current_lang]['invalid_input'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))
            
        elif choice == '3':
            email = input("\n" + colored(LANG[current_lang]['email_prompt'], 'yellow')).strip()
            if email:
                email_search(email)
            else:
                print("\n" + colored(LANG[current_lang]['invalid_input'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))
            
        elif choice == '4':
            ip = input("\n" + colored(LANG[current_lang]['ip_prompt'], 'yellow')).strip()
            if ip:
                ip_info(ip)
            else:
                print("\n" + colored(LANG[current_lang]['invalid_input'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))
            
        elif choice == '5':
            image_path = input("\n" + colored(LANG[current_lang]['image_prompt'], 'yellow')).strip()
            if image_path and os.path.exists(image_path):
                analyze_image(image_path)
            else:
                print("\n" + colored(LANG[current_lang]['invalid_input'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))
            
        elif choice == '6':
            print("\n" + colored(LANG[current_lang]['exiting'], 'red'))
            break
            
        else:
            print("\n" + colored(LANG[current_lang]['invalid_option'], 'red'))
            input("\n" + colored(LANG[current_lang]['press_enter'], 'yellow'))

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n" + colored(LANG[current_lang]['exiting'], 'red'))
        exit()