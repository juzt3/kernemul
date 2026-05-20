#include "register.hpp"

const hm::decoder_register hm::decoder_register::none = decoder_register(ZYDIS_REGISTER_NONE);
const hm::decoder_register hm::decoder_register::rip = decoder_register(ZYDIS_REGISTER_RIP);
const hm::decoder_register hm::decoder_register::rflags = decoder_register(ZYDIS_REGISTER_RFLAGS);
const hm::decoder_register hm::decoder_register::rax = decoder_register(ZYDIS_REGISTER_RAX);
const hm::decoder_register hm::decoder_register::rcx = decoder_register(ZYDIS_REGISTER_RCX);
const hm::decoder_register hm::decoder_register::rdx = decoder_register(ZYDIS_REGISTER_RDX);
const hm::decoder_register hm::decoder_register::rbx = decoder_register(ZYDIS_REGISTER_RBX);
const hm::decoder_register hm::decoder_register::rsi = decoder_register(ZYDIS_REGISTER_RSI);
const hm::decoder_register hm::decoder_register::rbp = decoder_register(ZYDIS_REGISTER_RBP);
const hm::decoder_register hm::decoder_register::rsp = decoder_register(ZYDIS_REGISTER_RSP);
const hm::decoder_register hm::decoder_register::rdi = decoder_register(ZYDIS_REGISTER_RDI);
const hm::decoder_register hm::decoder_register::r8 = decoder_register(ZYDIS_REGISTER_R8);
const hm::decoder_register hm::decoder_register::r9 = decoder_register(ZYDIS_REGISTER_R9);
const hm::decoder_register hm::decoder_register::r10 = decoder_register(ZYDIS_REGISTER_R10);
const hm::decoder_register hm::decoder_register::r11 = decoder_register(ZYDIS_REGISTER_R11);
const hm::decoder_register hm::decoder_register::r12 = decoder_register(ZYDIS_REGISTER_R12);
const hm::decoder_register hm::decoder_register::r13 = decoder_register(ZYDIS_REGISTER_R13);
const hm::decoder_register hm::decoder_register::r14 = decoder_register(ZYDIS_REGISTER_R14);
const hm::decoder_register hm::decoder_register::r15 = decoder_register(ZYDIS_REGISTER_R15);
