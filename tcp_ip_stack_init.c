

extern void init_spf_algo(void);
extern void isis_one_time_registration();

void init_tcp_ip_stack(void)
{
    init_spf_algo();
    isis_one_time_registration();
}