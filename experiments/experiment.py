from subprocess import Popen
import time
from random import sample, randint
from multiprocessing import Process

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


def GenerateBeautifulMAC(hostname):
    num = int(hostname[1:])
    if num > 99:
        raise ValueError
    res = str(num)
    if num < 10:
        res = '0' + res
    return f"00:00:00:00:00:{res}"


def GenerateBeautifulIP(hostname):
    num = int(hostname[1:])
    res = str(num)
    return f"10.0.0.{res}"


class OpenflowChainTopo(Topo):

    def build(self, k=2, n=1):
        self.hosts_number = k
        for j in range(n):
            switch_name = self.addSwitch(f's{j + 1}', protocols="OpenFlow13", listenPort=6666+j)
            for i in range(k):
                host_name = f'h{(j * k) + i + 1}'
                self.addHost(host_name)
                self.addLink(host_name, switch_name)
            if j != 0:
                self.addLink(f's{j}', f's{j + 1}')


class OpenflowCircleTopo(Topo):

    def build(self, k=2, n=1):
        self.hosts_number = k
        for j in range(n):
            switch_name = self.addSwitch(f's{j + 1}', protocols="OpenFlow13", listenPort=6666+j)
            for i in range(k):
                host_name = f'h{(j * k) + i + 1}'
                self.addHost(host_name)
                self.addLink(host_name, switch_name)
            if j != 0:
                self.addLink(f's{j}', f's{j + 1}')
        if n > 2:
            self.addLink(f's{j + 1}', 's1')


class OpenflowFullTopo(Topo):

    def build(self, k=2, n=1):
        self.hosts_number = k
        for j in range(n):
            switch_name = self.addSwitch(f's{j + 1}', protocols="OpenFlow13", listenPort=6666+j)
            for i in range(k):
                host_name = f'h{(j * k) + i + 1}'
                self.addHost(host_name)
                self.addLink(host_name, switch_name)
        for i in range(n):
            for j in range(i + 1, n):
                self.addLink(f's{i+1}', f's{j+1}')


class OpenflowStarTopo(Topo):

    def build(self, k=2, n=1):
        self.hosts_number = k
        self.addSwitch(f's1', protocols="OpenFlow13", listenPort=6665)
        for j in range(n):
            switch_name = self.addSwitch(f's{j + 2}', protocols="OpenFlow13", listenPort=6666+j)
            for i in range(k):
                host_name = f'h{(j * k) + i + 1}'
                self.addHost(host_name)
                self.addLink(host_name, switch_name)
            self.addLink(f's{j + 2}', f's1')


class OpenflowTreeTopo(Topo):

    def build(self, k=2, n=1):
        self.hosts_number = k
        current_switch_num = 1
        for j in range(n):
            for i in range(2 ** j):
                if current_switch_num < 9999:
                    switch_name = self.addSwitch(f's{current_switch_num}', protocols="OpenFlow13")
                    for i in range(k):
                        host_name = f'h{(current_switch_num - 1) * k + i + 1}'
                        self.addHost(host_name)
                        self.addLink(host_name, switch_name)
                    if j != 0:
                        self.addLink(f's{current_switch_num // 2}', f's{current_switch_num}')
                    current_switch_num += 1


class ExtendedCLI(CLI):

    def do_attack(self, args):
        """
        Make one host attack others.

        Parameters:
        h: attacker hostname
        t: time to attack
        """
        args = args.split()
        h = args[args.index('h') + 1]
        t = int(args[args.index('t') + 1])
        attacker = self.mn.get(h)
        p = Process(target=attacker.cmd,
                    args=[f'hping3 -i u6000 --rand-source {self.mn.get("h2").IP()}'])
        print(time.strftime('%H:%M:%S'))
        p.start()
        time.sleep(t)
        attacker.sendInt()
        p.terminate()
        attacker.cmd('killall hping3')

    def do_attack_several(self, args):
        """
        Make one host attack others.

        Parameters:
        n: attackers number
        t: time to attack
        """
        args = args.split()

        if 'n' in args:
            n = int(args[args.index('n') + 1])
        else:
            n = randint(1, 6)

        t = int(args[args.index('t') + 1])
        attackers_names = sample(list(set(self.mn.topo.hosts()) - set(['h2'])), k=n)
        print('attackers names: ', *[attackers_names])
        attackers = [self.mn.get(x) for x in attackers_names]
        self.last_attackers = attackers_names
        start_freq = 5000
        processes = []
        for attacker in attackers:
            attacker.cmd('killall hping3')
            victim_name = sample(list(set(self.mn.topo.hosts()) - set([attacker])), k=1)[0]
            victim_ip = self.mn.get(victim_name).IP()
            processes.append(Process(target=attacker.cmd,
                args=[f'hping3 -i u{start_freq * n} --rand-source {victim_ip}']))
        print(time.strftime('%H:%M:%S'))
        for p in processes:
            p.start()
        time.sleep(t)
        for attacker in attackers:
            attacker.sendInt()
            attacker.cmd('killall hping3')
        for p in processes:
            p.terminate()

    def do_non_attack(self, args):
        """
        Make one host communicate with others.

        Parameters:
        h: attacker hostname
        t: time to attack
        """
        args = args.split()
        h = args[args.index('h') + 1]
        t = int(args[args.index('t') + 1])
        comm_host = self.mn.get(h)
        for [num, host] in [[i + 1, self.mn.get(f'h{i + 1}')] for i
                          in range(self.mn.topo.hosts_number)
                          if f'h{i + 1}' != h]:
            comm_host.cmd(f'hping3 -i 1.5 {host.IP()} &')
        if t != 0:
            time.sleep(t)
            comm_host.cmd('killall hping3')

    def do_non_attack_fast(self, args):
        """
        Make one host communicate with others faster.

        Parameters:
        h: attacker hostname
        t: time to attack
        """
        args = args.split()
        h = args[args.index('h') + 1]
        t = int(args[args.index('t') + 1])
        comm_host = self.mn.get(h)
        for [num, host] in [[i + 1, self.mn.get(f'h{i + 1}')] for i
                          in range(self.mn.topo.hosts_number)
                          if f'h{i + 1}' != h]:
            comm_host.cmd(f'hping3 -i u2000 {host.IP()} &')
        if t != 0:
            time.sleep(t)
            comm_host.cmd('killall hping3')

    def do_ping_other(self, args):
        """
        Make one host communicate with one other.

        Parameters:
        h: attacker hostname
        t: time to attack
        """
        args = args.split()
        h = args[args.index('h') + 1]
        t = int(args[args.index('t') + 1])
        comm_host = self.mn.get(h)
        comm_host.cmd('killall hping3')
        host_name = sample(list(set(self.mn.topo.hosts()) - set([comm_host])), k=1)[0]
        comm_host.cmd(f'hping3 -i u250000 {self.mn.get(host_name).IP()} &')
        if t != 0:
            time.sleep(t)
            comm_host.cmd('killall hping3')

    def do_ping_other_all(self, args):
        """
        Make every host communicate with one other permanently.
        """
        for host_name in self.mn.topo.hosts():
            self.do_ping_other(f'h {host_name} t 0')
        

    def do_stop_hping(self, args):
        """
        Stop hpings on host.

        Parameters:
        h: host to operate
        """
        args = args.split()
        h = args[args.index('h') + 1]
        comm_host = self.mn.get(h)
        comm_host.cmd('killall hping3')

    def do_stop_hping_all(self, args):
        """
        Make every host communicate with one other permanently.
        """
        for host_name in self.mn.topo.hosts():
            self.do_stop_hping(f'h {host_name}')


if __name__ == '__main__':
    topo_num = int(input('enter topology id: '))
    hosts_number = int(input('enter hosts number: '))
    switch_number = int(input('enter switches number: '))
    controller = RemoteController('c0', ip='127.0.0.1', port=6653)

    match topo_num:
        case 1:
            print('Chain topology selected')
            topo = OpenflowChainTopo(k=hosts_number, n=switch_number)
        case 2:
            print('Circle topology selected')
            topo = OpenflowCircleTopo(k=hosts_number, n=switch_number)
        case 3:
            print('Full topology selected')
            topo = OpenflowFullTopo(k=hosts_number, n=switch_number)
        case 4:
            print('Star topology selected')
            topo = OpenflowStarTopo(k=hosts_number, n=switch_number)
        case 5:
            print('Tree topology selected '
                  '(switches num is used to count layers)')
            topo = OpenflowTreeTopo(k=hosts_number, n=switch_number)

    hosts_num = ((hosts_number * switch_number) if topo_num != 5
                 else hosts_number * (2 ** switch_number - 1))
    
    net = Mininet(topo=topo, controller=controller)
    for hostname in [f'h{i+1}' for i in range(hosts_num)]:
        host = net.get(hostname)
        host.config(mac=GenerateBeautifulMAC(hostname),
                    ip=GenerateBeautifulIP(hostname))
        print(f'{host.IP()}: {host.MAC()}')
    net.start()
    ExtendedCLI(net)
    net.stop()
