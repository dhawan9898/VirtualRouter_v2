

extern void init_spf_algo(void);
extern void isis_one_time_registration();
extern void ut_parser_init();

void init_tcp_ip_stack(void)
{
    init_spf_algo();
    isis_one_time_registration();
    ut_parser_init();
}