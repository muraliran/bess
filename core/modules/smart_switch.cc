// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Futurewei, Inc
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "smart_switch.h"
#include <algorithm>

/**
 * Utility Functions
 */



/**  Module impl   ********************/

const Commands SmartSwitch::cmds = {
    {"attach", "SmartSwitchAttachArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandAttach),
        Command::THREAD_UNSAFE},
    {"detach", "SmartSwitchDetachArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandDetach),
        Command::THREAD_UNSAFE},
    {"query_gate", "SmartSwitchQueryGateArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandQueryGate),
        Command::THREAD_UNSAFE},
};


CommandResponse SmartSwitch::Init(const bess::pb::SmartSwitchArg &arg) {
    // add the input datapaths as supported datapaths
    for (int i=0; i < arg.dp_ids_size(); i++) {
        datapaths.push_back(arg.dp_ids(i));
    }

    port_id_attr_id = AddMetadataAttr(PORT_ID_ATTR, PORT_ID_SIZE, 
                            bess::metadata::Attribute::AccessMode::kRead);
    if (port_id_attr_id < 1) {
        return CommandFailure(EINVAL, "Adding attribute PORT_ID failed");
    }

    return CommandSuccess();
}


void SmartSwitch::DeInit() {
    port_table.clear();
    datapaths.clear();
    free_gates.clear();
}


void SmartSwitch::ProcessBatch(bess::PacketBatch *batch) {
    gate_idx_t default_gate = ACCESS_ONCE(kDefaultGate);
    gate_idx_t out_gates[bess::PacketBatch::kMaxBurst];

    for (int i=0; i < batch->cnt(); i++) {
        out_gates[i] = default_gate;
        //bess::Packet *snb = batch->pkts()[i];
        int offset = bess::Packet::mt_offset_to_databuf_offset(attr_offset(port_id_attr_id));
        char *buf_addr = reinterpret_cast<char *>(batch->pkts()[i]->buffer());
        buf_addr += offset;
        // TODO: Convert 16 bytes to ascii and store in string
    }
    RunSplit(out_gates, batch);
}

CommandResponse SmartSwitch::CommandAttach(
        const bess::pb::SmartSwitchCommandAttachArg & arg) {
    // attach will send a response containing gate number
    bess::pb::SmartSwitchCommandAttachResponse resp;
    if ( std::find(datapaths.begin(), datapaths.end(), arg.dp_id()) ==
            datapaths.end()) {
        return CommandFailure(ENOENT, "datapath %s not found in the switch",
                                        arg.dp_id().c_str());
    }
    if (next_new_gate < kNumGates) {
        port_table[arg.port_id()] = next_new_gate;
        resp.set_gate(next_new_gate);
        next_new_gate++;
    } else {
        if (free_gates.size() > 0) {
            port_table[arg.port_id()] = free_gates.back();
            free_gates.pop_back();
        } else {
            return CommandFailure(EINVAL,
                    "Max %d gates. No more gates free to allocate.",
                    kNumGates);
        }
    }

    return CommandSuccess(resp);
}

CommandResponse SmartSwitch::CommandDetach(
        const bess::pb::SmartSwitchCommandDetachArg & arg) {
    guid_int_map::iterator it;
    if ((std::find(datapaths.begin(), datapaths.end(), arg.dp_id()) !=
             datapaths.end()) ||
            (it = port_table.find(arg.port_id())) !=  port_table.end()) {
        free_gates.push_back(it->second);
        port_table.erase(it);
    } else {
        return CommandFailure(ENOENT,
                "datapath %s or port %s not in the switch",
                arg.dp_id().c_str(), arg.port_id().c_str());
    }
    return CommandSuccess();
}

CommandResponse SmartSwitch::CommandQueryGate(
        const bess::pb::SmartSwitchCommandQueryGateArg & arg) {
    guid_int_map::iterator it;
    bess::pb::SmartSwitchCommandQueryGateResponse resp;
    if ((it = port_table.find(arg.port_id())) !=  port_table.end()) {
        resp.set_gate(it->second);
    } else {
        return CommandFailure(ENOENT,
                "port %s not found in the switch",
                arg.port_id().c_str());
    }
    return CommandSuccess(resp);
}

ADD_MODULE(SmartSwitch, "smart_switch",
           "classifies packets based on internal dest port id")

