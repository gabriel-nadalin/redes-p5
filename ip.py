from iputils import *
#biblioteca dita como melhor para fazer operacoes com endereços de ip
import ipaddress

class CIDR:
    def __init__(self, cidr):
        self.address, self.n = tuple(cidr.split('/'))
        self.n = int(self.n)
        self.prefix = int.from_bytes(str2addr(self.address), 'big') >> 32 - self.n

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)

            #decrementa o datagrama
            ttl -= 1

            #descarta o datagrama e retorna ele ao remetente (usa ICMP - informa que o pacote nao foi entregue e o devolve)
            if (ttl == 0):
                #remetente - src_addr
                # 11 - flag pra indicar o problema la
                checksum = calc_checksum(struct.pack('>BBHI', 11, 0, 0, 0) + datagrama[:28])
                self.enviar((struct.pack('>BBHI', 11, 0, 0, checksum) + datagrama[:28]), src_addr, 1)
                return
            
            #  nesse caso ja tem as infos prontas separadas  - cabecalho bem explicado no "enviar"
            cabecalho = struct.pack('>BBHHHBBH', 0x45, dscp | ecn, (20 + len(payload)), identification,  (flags << 13) | frag_offset, ttl, proto, 0)
            cabecalho += str2addr(src_addr) +str2addr(dst_addr)

            #faz o checksum
            cabecalho_final = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(payload)), identification,  (flags << 13) | frag_offset, ttl, proto, calc_checksum(cabecalho))

            cabecalho_final += str2addr(src_addr) +str2addr(dst_addr)

            #o datagrama é o cabecalho + o payload
            datagrama = cabecalho_final + payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        next_hop = None
        max_n = -1
        for cidr in self.tabela:
            if int.from_bytes(str2addr(dest_addr), 'big') >> 32 - cidr.n == cidr.prefix:
                if cidr.n > max_n:
                    next_hop = self.tabela[cidr]
                    max_n = cidr.n
        return next_hop


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = {}
        for x in tabela:
            cidr, next_hop = x
            self.tabela[CIDR(cidr)] = next_hop


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocolo = 6):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        #formato cabecalho
        #  Version - 4; IHL - 20 (5); DSCP, ECN - 0; Tamanho Total - 20 + tam do segmento; id - incrementa fragmentaçao; flags, fo, - 0; time to live (max de roteadores) - 64 no linux; protocolo - 6 (do TCP) ou 1 (do ICMP); checksum -  cabecalho - 0, cabecalho_final calc_checksum(cabecalho)- precisa anexar o meu enrereço com o destino ao header
        cabecalho = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(segmento)), self.id,  0, 64, protocolo, 0)
        cabecalho += str2addr(self.meu_endereco) +str2addr(dest_addr)

        #faz o checksum
        cabecalho_final = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(segmento)), self.id,  0, 64, protocolo, calc_checksum(cabecalho))

        cabecalho_final += str2addr(self.meu_endereco) +str2addr(dest_addr)

        #incrementa o id toda vez que essa poeracao ocorre
        self.id += 1

        #o datagrama é o cabecalho + o segmento
        datagrama = cabecalho_final + segmento

        self.enlace.enviar(datagrama, next_hop)
