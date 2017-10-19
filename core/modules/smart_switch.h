// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Futurewei Inc.
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

#ifndef BESS_MODULES_SMARTSWITCH_H_
#define BESS_MODULES_SMARTSWITCH_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../pb/caese_msg.pb.h"
#include "../utils/autouuid.h"

#include <map>
#include <vector>
#include <string>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error this code assumes little endian architecture (x86)
#endif

typedef std::map< std::string, gate_idx_t > str_int_map;
typedef std::vector< std::string >  string_vector;

// Offset definitions
// NOTE: Max 32 bytes metadata per module 128 max
#define PORT_ID_OFFSET   0
#define PORT_ID_SIZE     16
#define PORT_ID_ATTR     "Port_ID"
#define FLOW_ID_OFFSET   16
#define FLOW_ID_SIZE     1
#define FLOW_ID_ATTR     "Flow_ID"


class SmartSwitch final : public Module {
 public:
  enum Direction {
   kForward = 0,
   kReverse = 1,
  };
  static const Commands cmds;
  static const gate_idx_t kNumOGates = 256;  // both in & out each
  static const gate_idx_t kNumIGates = 256;  // both in & out each

  SmartSwitch() : Module(), next_new_gate_(1) {
            max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::SmartSwitchArg &arg);

  void DeInit() override;

  void ProcessBatch(bess::PacketBatch *batch) override;

  CommandResponse CommandAddAttributes(const bess::pb::SmartSwitchCommandAddAttributesArg &arg); 
  CommandResponse CommandAttach(const bess::pb::SmartSwitchCommandAttachArg &arg); 
  CommandResponse CommandDetach(const bess::pb::SmartSwitchCommandDetachArg &arg); 
  CommandResponse CommandQueryGate(const bess::pb::SmartSwitchCommandQueryGateArg &arg);

 private:
  const gate_idx_t kNumGates = SmartSwitch::kNumOGates;
  const gate_idx_t kDefaultGate = 0; // both in & out

  str_int_map port_table_; // port_id to gate mapping
  str_int_map fdb_table_;   // mac address to gate mapping
  string_vector datapaths_;
  gate_idx_t   next_new_gate_;
  std::vector<gate_idx_t> free_gates_;
};


#endif   // BESS_MODULES_SMARTSWITCH_H_
