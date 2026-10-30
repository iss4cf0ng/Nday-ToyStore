# simulate_ms12020.py
# Simulation program

import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--normal', action='store_true', help='Normal RDP connection')
parser.add_argument('--check', action='store_true', help='Check vulnerability')
parser.add_argument('--dos', action='store_true', help='DoS')

args = parser.parse_args()

class ChannelObject:
    def __init__(self, channel_id):
        self.channel_id = channel_id
        self.is_free = False

    def __repr__(self):
        return f'<Channel ID: {self.channel_id} (Free={"True" if self.is_free else "False"})>'

class SList:
    def __init__(self, capacity=4):
        self.capacity = capacity
        self.entries = [None] * capacity
        self.count = 0

    def append(self, obj):
        if self.count >= self.capacity:
            old_cap = self.capacity
            self.capacity *= 2

            print(f'[Pool Expansion] Queue is full ({old_cap}), triggering FUN_0002bf8a to double capacity to {self.capacity}')

            new_entries = [None] * self.capacity
            for i in range(self.count):
                new_entries[i] = self.entries[i]
            
            self.entries = new_entries

        self.entries[self.count] = obj
        self.count += 1

    def remove(self, target_id):
        for idx in range(self.count):
            obj = self.entries[idx]
            if obj and obj.channel_id == target_id:
                print(f'[_SListRemove]: Found target <{target_id}> on index={idx}')

                last_idx = self.count - 1
                last_obj = self.entries[last_idx]

                print(f'[Bad overwrite]: Replace <{idx}> with the last element with channel_id <{last_obj.channel_id}>')

                self.entries[idx] = last_obj
                self.entries[last_idx] = None # free()
                self.count -= 1

                return obj

        return None

class MockVulRDPServer:
    def __init__(self):
        self.user_channels = SList()
        self.global_channels = {}

    def handle_client_connect(self, mode):
        print(f'----------------------------------------')
        print(f'\tNew connection: mode={mode}')
        print(f'----------------------------------------')

        self.user_channels = SList()
        self.global_channels = {}

        if mode == 'NORMAL':
            print('[+] Normal RDP user has been joined to channel_id=1001')

            obj = ChannelObject(1001)
            self.user_channels.append(obj)
            self.global_channels[1001] = obj

        elif mode == 'CHECK':
            print('[+] Check vulnerability: Reusing channel 1002')

            obj = ChannelObject(1002)
            self.user_channels.append(obj) 
            self.user_channels.append(obj)
            self.global_channels[1002] = obj

            print('No any rejection, server is vulnerable')
        elif mode == 'DOS':
            print('[+] DoS ( . _ .)')

            shared_obj = ChannelObject(1002)
            self.user_channels.append(shared_obj)
            self.global_channels[1002] = shared_obj

            for dummy_id in range(10, 22):
                self.user_channels.append(ChannelObject(dummy_id))

            self.user_channels.append(shared_obj)

            print(f'[*] Count of channel object in channel 1002: {self.user_channels.count}')
            print(f'[+] Server is cookedddddddd')

        else:
            print('[-] What the hell is this?')

    def channel_leave(self, target_id):
        print(f'[*] Doing _ChannelLeave to remove channel_id={target_id}')

        removed_obj = self.user_channels.remove(target_id)

        if not removed_obj:
            raise RuntimeError(f'Cannot find channel with id: {target_id}')

        if removed_obj.is_free:
            raise RuntimeError(f'Double Free / User-After-Free. Channel_id={target_id}')
        else:
            print(f'[+] Successfully released channel_id={target_id}')
            removed_obj.is_free = True

    def detach_user(self):
        print('[*] DetachUser API')

        idx = 0
        while idx < self.user_channels.count:
            current_entry = self.user_channels.entries[idx]
            if current_entry is None:
                break

            current_id = current_entry.channel_id
            print(f'[Iteration] Current Index={idx}. Channel ID={current_id}')

            self.channel_leave(current_id)

            if idx >= self.user_channels.count:
                break

            if self.user_channels.capacity > 4:
                if current_id != 1002:
                    idx += 1
            else:
                idx += 1

def main():
    mode = ''
    if args.normal:
        mode = 'NORMAL'
    elif args.check:
        mode = 'CHECK'
    elif args.dos:
        mode = 'DOS'
    else:
        parser.print_help()
        return

    server = MockVulRDPServer()
    server.handle_client_connect(mode)
    
    try:
        server.detach_user()
    except RuntimeError as ex:
        print('\n')
        print(
            ':( A problem has been detected and detected and Windows has been shut down to prevent damage to your computer.\n' +
            '\n' +
            f'{ex}' +
            '\n' +
            'If this is the first time you\'ve seen this error screen, restart your computer... alright, that\'s it.'
        )
        print('\n')

if __name__ == '__main__':
    main()
