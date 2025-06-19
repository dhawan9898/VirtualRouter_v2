#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__


typedef struct isis_intf_info_{

}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) (isis_intf_info_t *)(intf_ptr->intf_nw_prop.isis_intf_info)

#endif