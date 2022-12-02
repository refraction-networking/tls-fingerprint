#ifndef _INCLGUARD_CLONERING_RUST_INTERFACE_H_
#define _INCLGUARD_CLONERING_RUST_INTERFACE_H_

struct RustGlobalsStruct
{
    void* ft; // FlowTracker
};

struct RustGlobalsStruct rust_init(uint8_t core_id, int cores_total, char* db_source_name, size_t gre_offset);
uint8_t rust_process_packet(void* rust_global, void* c_raw_ethframe, size_t c_frame_len);
uint8_t rust_periodic_cleanup(void* rust_global);
uint8_t rust_print_avg_stats(void* rust_global);
#endif //_INCLGUARD_CLONERING_RUST_INTERFACE_H_
