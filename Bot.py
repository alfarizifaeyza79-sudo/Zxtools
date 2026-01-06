import requests
import threading
import random
import time
from colorama import init, Fore

init(autoreset=True)

class BlooketBot:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://api.blooket.com/api"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def join_game(self, pin, bot_name, game_mode=""):
        """Bergabung ke game dengan PIN"""
        try:
            # Cek status game
            check_url = f"{self.base_url}/games"
            data = {
                "pin": pin
            }
            
            response = self.session.post(check_url, json=data, headers=self.headers)
            
            if response.status_code == 200:
                game_data = response.json()
                print(f"{Fore.GREEN}[+] Game ditemukan: {game_data.get('name', 'Unknown')}")
                
                # Bergabung ke game
                join_url = f"{self.base_url}/client"
                join_data = {
                    "name": bot_name,
                    "pin": pin
                }
                
                join_response = self.session.post(join_url, json=join_data, headers=self.headers)
                
                if join_response.status_code == 200:
                    player_data = join_response.json()
                    print(f"{Fore.GREEN}[+] Bot '{bot_name}' berhasil bergabung!")
                    print(f"{Fore.CYAN}[i] Player ID: {player_data.get('id', 'N/A')}")
                    
                    # Untuk game yang membutuhkan mode
                    if game_mode:
                        mode_url = f"{self.base_url}/games/{game_mode}/players"
                        mode_data = {
                            "playerId": player_data.get('id'),
                            "name": bot_name
                        }
                        self.session.post(mode_url, json=mode_data, headers=self.headers)
                    
                    return True
                else:
                    print(f"{Fore.RED}[-] Gagal bergabung: {join_response.status_code}")
                    return False
                    
            else:
                print(f"{Fore.RED}[-] Game tidak ditemukan atau PIN salah")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}")
            return False
    
    def answer_questions(self, player_id, correct_answers=True):
        """Mengirim jawaban (contoh sederhana)"""
        # Implementasi menjawab pertanyaan
        # Note: Ini sangat bergantung pada struktur game spesifik
        pass

def create_bots(pin, num_bots, base_name="Bot"):
    """Membuat beberapa bot sekaligus"""
    bot = BlooketBot()
    threads = []
    
    print(f"{Fore.YELLOW}[*] Memulai {num_bots} bot...")
    
    for i in range(1, num_bots + 1):
        bot_name = f"{base_name}_{i:03d}"
        
        thread = threading.Thread(
            target=bot.join_game,
            args=(pin, bot_name)
        )
        threads.append(thread)
        thread.start()
        
        # Delay antar bot untuk menghindari detection
        time.sleep(random.uniform(0.5, 1.5))
    
    # Tunggu semua thread selesai
    for thread in threads:
        thread.join()
    
    print(f"{Fore.GREEN}[√] Semua bot telah dijalankan!")

def main():
    print(f"{Fore.CYAN}╔{'═'*50}╗")
    print(f"{Fore.CYAN}║{'BLOOKET BOT CREATOR':^50}║")
    print(f"{Fore.CYAN}╚{'═'*50}╝")
    
    # Input dari user
    pin = input(f"{Fore.YELLOW}[?] Masukkan PIN game: ").strip()
    
    try:
        num_bots = int(input(f"{Fore.YELLOW}[?] Jumlah bot: ").strip())
    except ValueError:
        print(f"{Fore.RED}[-] Masukkan angka yang valid!")
        return
    
    base_name = input(f"{Fore.YELLOW}[?] Nama dasar bot (default: Bot): ").strip()
    if not base_name:
        base_name = "Bot"
    
    # Konfirmasi
    print(f"\n{Fore.WHITE}[*] Konfigurasi:")
    print(f"{Fore.WHITE}    PIN: {pin}")
    print(f"{Fore.WHITE}    Jumlah bot: {num_bots}")
    print(f"{Fore.WHITE}    Nama bot: {base_name}_XXX")
    
    confirm = input(f"\n{Fore.YELLOW}[?] Lanjutkan? (y/n): ").lower()
    
    if confirm == 'y':
        create_bots(pin, num_bots, base_name)
    else:
        print(f"{Fore.RED}[-] Dibatalkan")

if __name__ == "__main__":
    main()
