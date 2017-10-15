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

//using bess::snbuff_layout::SNBUF_METADATA_OFF;

/**  Module impl   ********************/

const Commands SmartSwitch::cmds = {
    {"attach", "SmartSwitchCommandAttachArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandAttach),
        Command::THREAD_UNSAFE},
    {"detach", "SmartSwitchCommandDetachArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandDetach),
        Command::THREAD_UNSAFE},
    {"query_gate", "SmartSwitchCommandQueryGateArg",
        MODULE_CMD_FUNC(&SmartSwitch::CommandQueryGate),
        Command::THREAD_UNSAFE},
};


CommandResponse SmartSwitch::Init(const bess::pb::SmartSwitchArg &arg) {
    // add the input datapaths as supported datapaths
    for (int i=0; i < arg.dp_ids_size(); i++) {
        datapaths_.push_back(arg.dp_ids(i));
    }

    int attr_id = AddMetadataAttr("Port_ID", 16, 
                            bess::metadata::Attribute::AccessMode::kRead);
    if (attr_id < 0) {
        return CommandFailure(EINVAL, "Adding attribute Port_ID failed with attr_id = %d", attr_id);
    } else {
        attr_id = AddMetadataAttr("PortNo", 1, bess::metadata::Attribute::AccessMode::kRead);
        if (attr_id < 0) {
            return CommandFailure(EINVAL, "Adding attribute Port_ID failed with attr_id = %d", attr_id);
        }
    }

    return CommandSuccess();
}


void SmartSwitch::DeInit() {
    port_table_.clear();
    datapaths_.clear();
    free_gates_.clear();
}


void SmartSwitch::ProcessBatch(bess::PacketBatch *batch) {
    gate_idx_t default_gate = ACCESS_ONCE(kDefaultGate);
    gate_idx_t out_gates[bess::PacketBatch::kMaxBurst];

    int cnt = batch->cnt();

    for (int i=0; i < cnt; i++) {
        out_gates[i] = default_gate;

        bess::Packet *pkt = batch->pkts()[i];
        uint8_t* buf_port_id = get_attr<uint8_t*>(this, 0, pkt);
        
        // TODO: fix the 16 byte retrieval above
        buf_port_id=0;  // workaround

        int8_t gate_no = -1;
        if (buf_port_id) {
            bess::utils::Autouuid portid(buf_port_id);
            gate_no =  port_table_[portid.get_struuid()];
        }
        const uint8_t port_no = get_attr<uint8_t>(this, 1, pkt);
        if (gate_no < 0)
            out_gates[i] = port_no;
        else
            out_gates[i] = gate_no;
    }
    RunSplit(out_gates, batch);
}

CommandResponse SmartSwitch::CommandAttach(
        const bess::pb::SmartSwitchCommandAttachArg & arg) {
    // attach will send a response containing gate number
    bess::pb::SmartSwitchCommandAttachResponse resp;
    if ( std::find(datapaths_.begin(), datapaths_.end(), arg.dp_id()) ==
            datapaths_.end()) {
        return CommandFailure(ENOENT, "datapath %s not found in the switch",
                                        arg.dp_id().c_str());
    }
    if (next_new_gate_ < kNumGates) {
        port_table_[arg.port_id()] = next_new_gate_;
        resp.set_gate(next_new_gate_);
        next_new_gate_++;
    } else {
        if (free_gates_.size() > 0) {
            port_table_[arg.port_id()] = free_gates_.back();
            free_gates_.pop_back();
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
    str_int_map::iterator it;
    if ((std::find(datapaths_.begin(), datapaths_.end(), arg.dp_id()) !=
             datapaths_.end()) ||
            (it = port_table_.find(arg.port_id())) !=  port_table_.end()) {
        free_gates_.push_back(it->second);
        port_table_.erase(it);
    } else {
        return CommandFailure(ENOENT,
                "datapath %s or port %s not in the switch",
                arg.dp_id().c_str(), arg.port_id().c_str());
    }
    return CommandSuccess();
}

CommandResponse SmartSwitch::CommandQueryGate(
        const bess::pb::SmartSwitchCommandQueryGateArg & arg) {
    str_int_map::iterator it;
    bess::pb::SmartSwitchCommandQueryGateResponse resp;
    if ((it = port_table_.find(arg.port_id())) !=  port_table_.end()) {
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

