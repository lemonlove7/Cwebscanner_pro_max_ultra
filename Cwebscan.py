#!/usr/bin/env python
#coding:utf-8
#Author:lemonlove7
#c段web应用信息扫描工具pro max ultra版
import IPy
import sys
import gevent
import csv

import gevent.monkey
gevent.monkey.patch_all()
 
import ssl

import threading,queue

import argparse
import time
import socket
import requests
import dns.resolver
from gevent import monkey
from bs4 import BeautifulSoup
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.dummy import Lock
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import importlib
importlib.reload(sys)
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
monkey.patch_all()


class Scanner(object):
    def __init__(self, target, threads, custom_ports,filename_time):
        self.W            = '\033[0m'
        self.G            = '\033[1;32m'
        self.O            = '\033[1;33m'
        self.R            = '\033[1;31m'
        self.custom_ports = custom_ports
        self.server       = target
        self.result       = []
        self.ips          = []
        self.time         = time.time()
        self.threads      = threads
        self.lock         = Lock()
        self.target = self.handle_target()
        self.get_ip_addr()
        self.def_port=[80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880]
        self.filename_time=filename_time

    def handle_target(self):
        #处理给定扫描目标
        try:
            if int(self.server.split('.')[-1]) >= 0:
                return '.'.join(self.server.split('.')[:3])+'.0/24'
        except:
            if not self.check_cdn():
                return '.'.join(i for i in socket.gethostbyname(self.server).split('.')[:3])+'.0/24'
            else:
                print(u'{}[-] 目标使用了CDN, 停止扫描...{}'.format(self.R, self.W))
                sys.exit(1)

    def check_cdn(self):
        #cdn检测
        myResolver = dns.resolver.Resolver()
        myResolver.lifetime = myResolver.timeout = 2.0
        dnsserver = [['114.114.114.114'],['8.8.8.8'],['223.6.6.6']]
        try:
            for i in dnsserver:
                myResolver.nameservers = i
                record = myResolver.resolver(self.server)
                self.result.append(record[0].address)
        except:
            pass
        finally:
            return True if len(set(list(self.result))) > 1 else False

    def get_ip_addr(self):
        #获取目标c段ip地址
        for ip in IPy.IP(self.target):
            self.ips.append(ip)

    def get_info(self, ip, port):
        url_types=['http://','https://']
        title=""
        serv=""
        try:
            for url_type in url_types:
                url    = f'{url_type}{str(ip)}:{str(port)}'
                header = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3)'}
                res = requests.get(url, timeout=10, headers=header, verify=False, allow_redirects=True)
                try:
                    serv   = res.headers['Server'].split()[0] if 'Server' in str(res.headers) else ''
                except:
                    pass
                try:
                    title  = BeautifulSoup(res.content,'lxml').title.text.strip('\n').strip()
                except:
                    pass
                result = '{}[+] {}{}{}{}{}'.format(self.G, url.ljust(28), str(res.status_code).ljust(6), serv.ljust(24), title,self.W)
                self.lock.acquire()
                print(result)
                with open(self.filename_time+'.csv', 'a+', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([url, str(res.status_code), serv,title])



                self.lock.release()
        except:
            pass
            
    def start(self, ip):
        #自定义扫描端口使用协程进行处理        
        if self.custom_ports:
            gevents = []
            for port in self.custom_ports.split(','):
                gevents.append(gevent.spawn(self.get_info, ip, port))
            gevent.joinall(gevents)
        else:
            gevents=[]
            for port in self.def_port:
                port=str(port)
                gevents.append(gevent.spawn(self.get_info, ip, port))
            gevent.joinall(gevents)
        
    def run(self):
        try:
            pool = ThreadPool(processes=self.threads)            
            pool.map_async(self.start, self.ips).get(0xffff)
            pool.close()
            pool.join()
        except Exception as e:
            pass
        except KeyboardInterrupt:
            print(u'\n[-] 用户终止扫描...')
            sys.exit(1)

def banner():
    banner = '''
   ______              __
  / ____/      _____  / /_  ______________ _____  ____  ___  _____
 / /   | | /| / / _ \/ __ \/ ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/   pro 
/ /___ | |/ |/ /  __/ /_/ (__  ) /__/ /_/ / / / / / / /  __/ /       max
\____/ |__/|__/\___/_.___/____/\___/\__,_/_/ /_/_/ /_/\___/_/        ultra

    '''
    print('\033[1;34m'+ banner +'\033[0m')
    print('-'*90)


def url_target():
    while not q.empty():
        target=q.get()
        myscan = Scanner(target, args.threads, args.custom_ports,filename_time)
        myscan.run()

def main():
    banner()
    filename_time=time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time()))
    parser = argparse.ArgumentParser(description='Example: python {} [xxx.txt] [-p8080,9090] '.format(sys.argv[0]))
    parser.add_argument('target', help=u'xxx.txt(默认扫描web常见端口)')
    parser.add_argument('-t', type=int, default=50, dest='threads', help=u'线程数(默认50)')
    parser.add_argument('-p', default=False, dest='custom_ports', help=u'自定义扫描端口(如-p8080,9090)')
    args   = parser.parse_args()

    with open(args.target, 'r') as f:
        targets = f.read().splitlines()
    q=queue.Queue()
    for target in targets:
        q.put(target)
    for i in range(10):
        t = threading.Thread(target=url_target)
        thread_list.append(t)
    for t in thread_list:
        t.setDaemon(True)
        t.start()
    for t in thread_list:
        t.join()


if __name__ == '__main__':
    start_time=time.time()
    thread_list = []
    q=queue.Queue()

    #########
    banner()
    filename_time=time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time()))
    parser = argparse.ArgumentParser(description='Example: python {} [xxx.txt] [-p8080,9090] '.format(sys.argv[0]))
    parser.add_argument('target', help=u'xxx.txt(默认扫描web常见端口)')
    parser.add_argument('-t', type=int, default=50, dest='threads', help=u'线程数(默认50)')
    parser.add_argument('-p', default=False, dest='custom_ports', help=u'自定义扫描端口(如-p8080,9090)')
    args   = parser.parse_args()

    with open(args.target, 'r') as f:
        targets = f.read().splitlines()
    q=queue.Queue()
    for target in targets:
        q.put(target)
    for i in range(args.threads):
        t = threading.Thread(target=url_target)
        thread_list.append(t)
    for t in thread_list:
        t.setDaemon(True)
        t.start()
    for t in thread_list:
        t.join()

    ########

    #main()
    print(u'{}[-] 扫描完成耗时: {} 秒.{}'.format('\033[1;33m', time.time() - start_time, '\033[0m'))
