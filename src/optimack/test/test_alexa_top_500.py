import csv
import sys
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.common.exceptions import TimeoutException, WebDriverException
import time, traceback, subprocess as sp, re, shlex, os, psutil, signal


def get_onload_time(driver, domain):
    try:
        url = 'http://' + domain
        driver.get(url)

        with open(out_dir+domain+".html", 'w') as douf:
            douf.writelines(driver.page_source)

        timing = driver.execute_script("return window.performance.timing")
        navigationStart = driver.execute_script("return window.performance.timing.navigationStart")
        responseStart = driver.execute_script("return window.performance.timing.responseStart")
        domContentLoaded = driver.execute_script("return window.performance.timing.domContentLoadedEventEnd")
        loadEventEnd = driver.execute_script("return window.performance.timing.loadEventEnd")

        timing['backendTime'] = responseStart - navigationStart
        timing['domContentLoadedTime'] = domContentLoaded - navigationStart
        timing['onLoadTime'] = loadEventEnd - navigationStart
        print("BackEnd: %fms" % (responseStart - navigationStart))
        print("DomContentLoaded: %fms" % (domContentLoaded - navigationStart))
        print("OnLoad: %fms" % (loadEventEnd - navigationStart))
        # print(timing.keys())
        return timing, 'Success'
    except TimeoutException as ex:
        print("driver.get timeout")
        return None, 'TIMEOUT'
    
    except WebDriverException as ex:
        print('selenium.common.exceptions.WebDriverException: Message: unknown error: net::ERR_PROXY_CONNECTION_FAILED')
        return None, 'PROXY_CONNECTION_FAILED'

    except:
        print('%s' % traceback.format_exc())
        return None, 'UNKNOWN_ERROR'

def open_normal_webdriver(domain):
    # Here chrome webdriver is used
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    #caps = DesiredCapabilities().CHROME
    #caps["pageLoadStrategy"] = "none"
    driver = webdriver.Chrome(executable_path='/root/https_test/chromedriver',chrome_options=chrome_options)
    driver.set_page_load_timeout(30)

    return driver

def open_proxy_webdriver(domain, proxy_addr):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    
    prox = Proxy()
    prox.proxy_type = ProxyType.MANUAL
    prox.http_proxy = proxy_addr
    # prox.socks_proxy = "ip_addr:port"
    # prox.ssl_proxy = proxy_addr

    capabilities = webdriver.DesiredCapabilities.CHROME
    prox.add_to_capabilities(capabilities)

    driver = webdriver.Chrome(executable_path='/root/https_test/chromedriver',desired_capabilities=capabilities, chrome_options=chrome_options)
    driver.set_page_load_timeout(300)

    return driver

def compare_pagesource(ndriver, pdriver):
    if ndriver.page_source == pdriver.page_source:
        print("Compare pagesource: True")
        return True
    else:
        with open("normal_page.html", "w") as nout:
            nout.writelines(ndriver.page_source)
        with open("proxy_page.html", "w") as pout:
            pout.writelines(pdriver.page_source)

        print("Compare pagesource: False")
        return False
        

def write_result(outfile, url, mode, timing_values):
    outfile.writelines(",".join([url, mode, timing_values]))

def exec(cmd):
    p = sp.Popen(shlex.split(cmd), encoding='utf8')
    out, err = p.communicate()

def start_squid(squid_path):
    exec("sudo " + squid_path)

def stop_squid(squid_path):
    exec("sudo " + squid_path + " -k shutdown")
    # exec(squid_path + " -k kill")

def start_tcpdump(domain, outfile):
    print("Starting tcpdump...")
    p = sp.Popen(["sudo", "tcpdump", "-i", "any", "-w", outfile, "tcp port 80"])
    return p

def stop_tcpdump(p):
    print("Stopping tcpdump...")
    os.system("sudo kill %d" % p.pid)


def test_normal(domain):
    normal_driver = open_normal_webdriver(domain)
    timing = get_onload_time(normal_driver)
    normal_driver.quit()
    print("Normal: " + str(timing))
    return normal_driver

def killall_process(process_name):
    for proc in psutil.process_iter():
        try:
            cmdline_name = ' '.join(proc.cmdline())
            # print(proc.name(), cmdline_name)
            if 'grep --color=auto' in proc.name():
                continue
            elif process_name.lower() in proc.name().lower() or process_name.lower in cmdline_name:
                # print("%d %s %s killed" %(proc.pid, proc.name(), cmdline_name))
                proc.terminate()
                proc.kill()
                # os.killpg(proc.pid, signal.SIGTERM)
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except:
            pass

    return False

def cleanup(tcpdump_p, squid_p, proxy_driver):
    # print("enter cleanup")
    # stop_tcpdump(tcpdump_p)
    # squid_p.terminate()
    # squid_p.kill()
    # os.system("sudo kill -9 %d" % squid_p.pid)
    exec("sudo iptables -F")
    exec("sudo iptables -t mangle -F")
    proxy_driver.close()
    proxy_driver.quit()
    # killall_process('squid')
    killall_process('chrome')
    # print(psutil.Process(squid_p.pid).children(recursive=True))
    # os.killpg(os.getpid(), signal.SIGTERM)
    time.sleep(2)


def test_proxy(domain, out_dir, outfile):

    try:
        count = 0
        while(count < 1):
            start_time = time.strftime("%Y%m%d%H%M%S")

            # tcpdump_outfile = out_dir + "pktdump_%s.pcap.%s" % (domain, start_time)
            # tcpdump_p = start_tcpdump(domain, tcpdump_outfile) 
            # squid_p = 0
            squid_p = sp.Popen(shlex.split(squid_path+" -N"), encoding='utf8', stdout=sp.PIPE)
            p = sp.Popen(shlex.split(squid_path+" -N | tee ~/rs/squid_output_%s_%s.log" % (domain, start_time)), stdout=sp.PIPE, encoding='utf8')
            time.sleep(5)

            proxy_driver = open_proxy_webdriver(domain, "127.0.0.1:3128")
            timing, err = get_onload_time(proxy_driver, domain)
            cleanup(0, squid_p, proxy_driver)

            output = [domain, 'Proxy', time.strftime("%Y-%m-%d %H:%M:%S"), err]
            if timing:
                output += list(map(str,timing.values()))
                outfile.writelines(','.join(output) + "\n")  
                # print("Proxy: " + str(timing))
                # os.system("sudo rm " + tcpdump_outfile)        
                break
            else:
                print("Proxy: failed, " + err)
                if err == 'UNKNOWN_ERROR' or count == 19:
                    with open(out_dir + "failed.txt", "a") as failf:
                        failf.writelines(domain + "," + err + "\n")
                    break
            count += 1


    except (KeyboardInterrupt, SystemExit):
        cleanup(0, 0, proxy_driver)
        pass

    except:
        print('%s' % traceback.format_exc())
        cleanup(0, squid_p, proxy_driver)

timing_keys = ['domain', 'mode', 'timestamp', 'ErrorCode', 'connectEnd', 'connectStart', 'domComplete', 'domContentLoadedEventEnd', 'domContentLoadedEventStart', 'domInteractive', 'domLoading', 'domainLookupEnd', 'domainLookupStart', 'fetchStart', 'loadEventEnd', 'loadEventStart', 'navigationStart', 'redirectEnd', 'redirectStart', 'requestStart', 'responseEnd', 'responseStart', 'secureConnectionStart', 'unloadEventEnd', 'unloadEventStart', 'backendTime', 'domContentLoadedTime', 'onLoadTime']

home_dir = os.path.expanduser("~") + "/"
out_dir = home_dir + "rs/browser/"
os.system("sudo mkdir -p "  + out_dir)
squid_path = home_dir + "squid/sbin/squid"
# test_normal("www.baidu.com")
with open(sys.argv[1], "r") as infile, open(out_dir + "browser_alexa_%s.txt" % time.strftime("%Y-%m-%dT%H:%M:%S"), "w") as outfile:
    # test_proxy(domain, out_dir, outfile)
    # test_proxy("www.twitch.tv", out_dir, outfile)
    # test_proxy("www.baidu.com", out_dir, outfile)

    outfile.writelines(','.join(timing_keys) + "\n")
    for line_num, line in enumerate(filter(None,infile.read().splitlines())):
        domain = line.strip().split(",")[0]
        print("Test: " + domain)
        test_proxy(domain, out_dir, outfile)
        print("\n")


