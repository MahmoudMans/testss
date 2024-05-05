from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
import time

def navigate_to_page_two(driver):
    WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.XPATH, "//nav[contains(@class, 'pagination')]"))
    )
    page_two_link = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//a[contains(@href, 'telecharger/bureautique/page/2/') and contains(text(), '2')]"))
    )
    if page_two_link:
        print("Clicking on page 2...")
        page_two_link.click()
        WebDriverWait(driver, 10).until(
            EC.url_contains("telecharger/bureautique/page/2/")
        )
        print("Arrived at page 2")
    else:
        print("Page 2 link not found.")

def scroll_and_click(element, driver):
    actions = ActionChains(driver)
    actions.move_to_element(element).perform()
    element.click()

def javascript_click(element, driver):
    driver.execute_script("arguments[0].click();", element)

def click_links_in_div(driver):
    WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.CSS_SELECTOR, "div.mt-6.grid.md\:grid-cols-2.lg\:grid-cols-1.xl\:grid-cols-2.gap-4"))
    )
    links = WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.CSS_SELECTOR, "div.mt-6.grid.md\:grid-cols-2.lg\:grid-cols-1.xl\:grid-cols-2.gap-4 a"))
    )
    for index in range(len(links)):
        links = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "div.mt-6.grid.md\:grid-cols-2.lg\:grid-cols-1.xl\:grid-cols-2.gap-4 a"))
        )
        link = links[index]
        print(f"Attempting to click on link {index + 1} found in the div...")
        try:
            scroll_and_click(link, driver)
        except Exception as e:
            print(f"Scroll and click failed: {str(e)}")
            javascript_click(link, driver)
        time.sleep(3)
        driver.back()
        time.sleep(3)

options = Options()
options.add_argument('--ignore-ssl-errors=yes')
options.add_argument('--ignore-certificate-errors')
options.add_argument('--allow-insecure-localhost')
options.add_argument('--disable-gpu')
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=options)

url = 'https://www.01net.com/telecharger/bureautique/'
driver.get(url)
time.sleep(5)

click_links_in_div(driver)
navigate_to_page_two(driver)
click_links_in_div(driver)  # Reuse the function to handle links on the second page

time.sleep(3)
driver.quit()
