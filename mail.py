import os
import sqlite3
import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InputFile
from aiogram.fsm.storage.memory import MemoryStorage
from dotenv import load_dotenv
import logging
import requests
import matplotlib.pyplot as plt
from datetime import datetime
from language import translations  # Import translations

# .env faylini yuklash
load_dotenv("token.env")
BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
METADEFENDER_API_KEY = os.getenv("METADEFENDER_API_KEY")

# Botni yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# Ma'lumotlar bazasi
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        warnings INTEGER DEFAULT 0,
        language TEXT DEFAULT 'uz'
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS blacklist (
        user_id INTEGER PRIMARY KEY
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        user_id INTEGER,
        file_name TEXT,
        scan_result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.commit()

# Til tanlash tugmalari
def language_keyboard():
    keyboard = ReplyKeyboardMarkup(
        resize_keyboard=True,
        keyboard=[
            [KeyboardButton(text="🇺🇿 O'zbek"), KeyboardButton(text="🇷🇺 Русский"), KeyboardButton(text="🇬🇧 English")]
        ]
    )
    return keyboard

# Asosiy menyu
def main_menu_keyboard(lang="uz"):
    keyboard = ReplyKeyboardMarkup(
        resize_keyboard=True,
        keyboard=[
            [KeyboardButton(text=translations["menu"][lang][0]), KeyboardButton(text=translations["menu"][lang][1])],
            [KeyboardButton(text=translations["menu"][lang][2]), KeyboardButton(text=translations["menu"][lang][3])],
            [KeyboardButton(text=translations["menu"][lang][4])]
        ]
    )
    return keyboard

# Admin menyu
def admin_menu_keyboard(lang="uz"):
    keyboard = main_menu_keyboard(lang)
    keyboard.add(KeyboardButton(text=translations["blacklist_menu"][lang]))
    return keyboard

# Bosqichma-bosqich javob berish
typing_stages = [
    "🤖 Antivirus botga xush kelibsiz...",
    "📂 Bu bot zararli dasturlarni tekshiradi...",
    "🛠 Tilni tanlang:"
]

async def animated_response(chat_id, texts, delay=1):
    message = await bot.send_message(chat_id, texts[0])
    for text in texts[1:]:
        await asyncio.sleep(delay)
        try:
            await message.edit_text(text)
        except Exception as e:
            logging.warning(f"Xabarni o'zgartirishda xatolik: {e}")

# Loading effect faqat "Tekshirilmoqda... 🚀" uchun
async def loading_effect(chat_id, initial_message="Tekshirilmoqda... 🚀"):
    loading_frames = ["🔄", "⏳", "⌛", "✅"]
    message = await bot.send_message(chat_id, initial_message)  # Birinchi marta ko'rsatish
    for frame in loading_frames:
        await asyncio.sleep(1)
        try:
            await message.edit_text(f"{frame} {initial_message}")
        except Exception as e:
            logging.warning(f"Xabarni o'zgartirishda xatolik: {e}")

@dp.message(lambda message: message.text == "/start")
async def start_command(message: types.Message):
    cursor.execute("INSERT OR IGNORE INTO users (user_id) VALUES (?)", (message.from_user.id,))
    conn.commit()
    await animated_response(message.chat.id, typing_stages, delay=1.5)
    await message.answer("🌍", reply_markup=language_keyboard())

@dp.message(lambda message: message.text in ["🇺🇿 O'zbek", "🇷🇺 Русский", "🇬🇧 English"])
async def set_language(message: types.Message):
    lang_map = {"🇺🇿 O'zbek": "uz", "🇷🇺 Русский": "ru", "🇬🇧 English": "en"}
    lang = lang_map.get(message.text)
    if lang:
        cursor.execute("UPDATE users SET language = ? WHERE user_id = ?", (lang, message.from_user.id))
        conn.commit()
        await bot.delete_message(message.chat.id, message.message_id)
        user_lang = lang
        sent_message = await message.answer(translations["send_file"][user_lang],
                                            reply_markup=main_menu_keyboard(user_lang))
        await asyncio.sleep(30)
        try:
            await sent_message.edit_text(translations["send_file"][user_lang])
        except Exception as e:
            logging.warning(f"Xabarni o'zgartirishda xatolik: {e}")
    else:
        await message.answer("❌ Noto'g'ri til tanlovi.")

@dp.message(lambda message: message.text in ["🌐 Tilni o'zgartirish", "🌐 Изменить язык", "🌐 Change Language"])
async def change_language(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    await message.answer(translations["choose_language"][user_lang], reply_markup=language_keyboard())

@dp.message(lambda message: message.document)
async def scan_file(message: types.Message):
    file_name = message.document.file_name
    await bot.delete_message(message.chat.id, message.message_id)  # Faylni o'chirish
    # Loading effect
    await loading_effect(message.chat.id)

    # Faylni VirusTotal orqali tekshirish
    file_info = await bot.get_file(message.document.file_id)
    file_path = file_info.file_path
    file_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    response = requests.get(file_url)
    file_data = response.content

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    files = {
        "file": (file_name, file_data)
    }
    vt_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    vt_data = vt_response.json()

    if 'error' in vt_data:
        await message.answer("❌ Faylni tekshirishda xatolik yuz berdi.")
        return

    analysis_id = vt_data["data"]["id"]
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    # Tekshirish natijasi
    vt_report_response = requests.get(report_url, headers=headers)
    vt_report_data = vt_report_response.json()

    malicious = vt_report_data["data"]["attributes"]["stats"]["malicious"]
    harmless = vt_report_data["data"]["attributes"]["stats"]["harmless"]
    total = malicious + harmless

    if total > 0:
        malicious_percentage = (malicious / total) * 100
        harmless_percentage = (harmless / total) * 100
    else:
        malicious_percentage = 0
        harmless_percentage = 0

    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    labels = [translations["malicious"][user_lang], translations["harmless"][user_lang]]
    sizes = [malicious_percentage, harmless_percentage]
    colors = ['red', 'green']
    explode = (0.1, 0)  # only "explode" the 1st slice

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    image_path = f"scan_result_{message.from_user.id}.png"
    plt.savefig(image_path)
    plt.close()

    scan_result_message = translations["scan_results"][user_lang].format(file_name=file_name)

    await message.answer(scan_result_message, reply_markup=main_menu_keyboard(user_lang))
    await bot.send_photo(message.chat.id, photo=InputFile(image_path))

    # Faylni skan qilish tarixiga yozib qo'yish
    cursor.execute("""
        INSERT INTO scan_history (user_id, file_name, scan_result)
        VALUES (?, ?, ?)
    """, (message.from_user.id, file_name, scan_result_message))
    conn.commit()

    # Faylni MetaDefender orqali tekshirish
    headers = {
        "apikey": METADEFENDER_API_KEY
    }
    files = {
        "file": (file_name, file_data)
    }
    md_response = requests.post("https://api.metadefender.com/v4/file", headers=headers, files=files)
    md_data = md_response.json()

    if 'error' in md_data:
        await message.answer("❌ Faylni tekshirishda xatolik yuz berdi.")
        return

    data_id = md_data["data_id"]
    md_report_url = f"https://api.metadefender.com/v4/file/{data_id}"

    # Tekshirish natijasi
    md_report_response = requests.get(md_report_url, headers=headers)
    md_report_data = md_report_response.json()

    md_malicious = md_report_data["scan_results"]["scan_all_result_a"]
    md_harmless = 100 - md_malicious

    labels = [translations["malicious"][user_lang], translations["harmless"][user_lang]]
    sizes = [md_malicious, md_harmless]
    colors = ['red', 'green']
    explode = (0.1, 0)  # only "explode" the 1st slice

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    image_path = f"scan_result_md_{message.from_user.id}.png"
    plt.savefig(image_path)
    plt.close()

    await bot.send_photo(message.chat.id, photo=InputFile(image_path))

@dp.message(lambda message: message.text in ["📊 Statistika", "📊 Статистика", "📊 Statistics"])
async def send_statistics(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]
    # Show loading effect
    await loading_effect(message.chat.id, translations["preparing_statistics"][user_lang])

    cursor.execute("SELECT timestamp FROM scan_history")
    timestamps = cursor.fetchall()
    if not timestamps:
        await message.answer("📊 Hali hech qanday fayl tekshirilmagan.")
        return

    # Parse dates correctly
    days = [datetime.strptime(ts[0].split()[0], "%Y-%m-%d").date() for ts in timestamps]
    day_counts = {day: days.count(day) for day in set(days)}
    sorted_days = sorted(day_counts.keys())
    values = [day_counts[day] for day in sorted_days]

    plt.figure(figsize=(10, 6))
    plt.bar(sorted_days, values, color='blue')
    plt.xlabel("Sana")
    plt.ylabel("Tekshirilgan fayllar soni")
    plt.title("📊 Tekshiruv statistikasi")
    plt.xticks(rotation=45)
    plt.grid(axis='y')
    plt.tight_layout()

    bar_image_path = "statistics_bar.png"
    plt.savefig(bar_image_path)
    plt.close()

    cursor.execute("SELECT scan_result FROM scan_history")
    scan_results = cursor.fetchall()
    if not scan_results:
        await message.answer("📊 Hali hech qanday fayl tekshirilmagan.")
        return

    malicious_count = sum(1 for result in scan_results if "Zararli" in result[0] or "Вредоносный" in result[0] or "Malicious" in result[0])
    harmless_count = len(scan_results) - malicious_count

    labels = [translations["malicious"][user_lang], translations["harmless"][user_lang]]
    sizes = [malicious_count, harmless_count]
    colors = ['red', 'green']
    explode = (0.1, 0)  # only "explode" the 1st slice

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    pie_image_path = "statistics_pie.png"
    plt.savefig(pie_image_path)
    plt.close()

    await bot.send_photo(message.chat.id, photo=open(bar_image_path, 'rb'))
    await bot.send_photo(message.chat.id, photo=open(pie_image_path, 'rb'))

@dp.message(lambda message: message.text in ["📝 Tekshiruv tarixi", "📝 История проверок", "📝 Scan History"])
async def scan_history(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    cursor.execute("SELECT file_name, scan_result, timestamp FROM scan_history WHERE user_id = ?", (message.from_user.id,))
    history = cursor.fetchall()

    if not history:
        await message.answer("📊 Hali hech qanday fayl tekshirilmagan.")
        return

    history_message = ""
    for file_name, scan_result, timestamp in history:
        history_message += f"📁 {file_name}\n🕒 {timestamp}\n🔍 {scan_result}\n\n"

    await message.answer(history_message)

@dp.message(lambda message: message.text in ["ℹ️ Dastur haqida", "ℹ️ О программе", "ℹ️ About"])
async def about(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    await message.answer(translations["about"][user_lang])

@dp.message(lambda message: message.text in ["🔄 Yordam", "🔄 Помощь", "🔄 Help"])
async def help(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    await message.answer(translations["help"][user_lang])

@dp.message(lambda message: message.chat.type in ["group", "supergroup"])
async def group_message_handler(message: types.Message):
    if message.document:
        user_id = message.from_user.id
        cursor.execute("SELECT warnings FROM users WHERE user_id = ?", (user_id,))
        warnings = cursor.fetchone()[0]

        if warnings == 1:
            cursor.execute("INSERT INTO blacklist (user_id) VALUES (?)", (user_id,))
            conn.commit()
            cursor.execute("SELECT language FROM users WHERE user_id = ?", (user_id,))
            user_lang = cursor.fetchone()[0]
            await message.answer(translations["blacklisted"][user_lang])
        else:
            warnings += 1
            cursor.execute("UPDATE users SET warnings = ? WHERE user_id = ?", (warnings, user_id))
            conn.commit()
            cursor.execute("SELECT language FROM users WHERE user_id = ?", (user_id,))
            user_lang = cursor.fetchone()[0]
            await message.answer(translations["blacklist_warning"][user_lang])
    else:
        await scan_file(message)

@dp.message(lambda message: message.text in ["🛠 Qora ro'yhat", "🛠 Черный список", "🛠 Blacklist"])
async def blacklist(message: types.Message):
    cursor.execute("SELECT language FROM users WHERE user_id = ?", (message.from_user.id,))
    user_lang = cursor.fetchone()[0]

    cursor.execute("SELECT user_id FROM blacklist")
    blacklisted_users = cursor.fetchall()

    if not blacklisted_users:
        await message.answer("🛠 Qora ro'yhat bo'sh.")
        return

    blacklist_message = "🛠 Qora ro'yhat:\n\n"
    for user_id in blacklisted_users:
        blacklist_message += f"🔒 User ID: {user_id[0]}\n"

    await message.answer(blacklist_message)

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())