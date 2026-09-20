#include "register.hpp"

const hm::decoder_reg hm::decoder_reg::none = decoder_reg(ZYDIS_REGISTER_NONE);
const hm::decoder_reg hm::decoder_reg::rip = decoder_reg(ZYDIS_REGISTER_RIP);
const hm::decoder_reg hm::decoder_reg::rflags = decoder_reg(ZYDIS_REGISTER_RFLAGS);
const hm::decoder_reg hm::decoder_reg::rax = decoder_reg(ZYDIS_REGISTER_RAX);
const hm::decoder_reg hm::decoder_reg::rcx = decoder_reg(ZYDIS_REGISTER_RCX);
const hm::decoder_reg hm::decoder_reg::rdx = decoder_reg(ZYDIS_REGISTER_RDX);
const hm::decoder_reg hm::decoder_reg::rbx = decoder_reg(ZYDIS_REGISTER_RBX);
const hm::decoder_reg hm::decoder_reg::rsi = decoder_reg(ZYDIS_REGISTER_RSI);
const hm::decoder_reg hm::decoder_reg::rbp = decoder_reg(ZYDIS_REGISTER_RBP);
const hm::decoder_reg hm::decoder_reg::rsp = decoder_reg(ZYDIS_REGISTER_RSP);
const hm::decoder_reg hm::decoder_reg::rdi = decoder_reg(ZYDIS_REGISTER_RDI);
const hm::decoder_reg hm::decoder_reg::r8 = decoder_reg(ZYDIS_REGISTER_R8);
const hm::decoder_reg hm::decoder_reg::r9 = decoder_reg(ZYDIS_REGISTER_R9);
const hm::decoder_reg hm::decoder_reg::r10 = decoder_reg(ZYDIS_REGISTER_R10);
const hm::decoder_reg hm::decoder_reg::r11 = decoder_reg(ZYDIS_REGISTER_R11);
const hm::decoder_reg hm::decoder_reg::r12 = decoder_reg(ZYDIS_REGISTER_R12);
const hm::decoder_reg hm::decoder_reg::r13 = decoder_reg(ZYDIS_REGISTER_R13);
const hm::decoder_reg hm::decoder_reg::r14 = decoder_reg(ZYDIS_REGISTER_R14);
const hm::decoder_reg hm::decoder_reg::r15 = decoder_reg(ZYDIS_REGISTER_R15);
