#ifndef SR_BUSINESS_LOGIC_H 
#define SR_BUSINESS_LOGIC_H

#include "sr_info.h"

/* Content of this structure depends on the business logic of the data-user */
sr_details g_du_business_logics[] = {
    /* Service 0 is a service running on simulated enclave */
    {
        0, /* Ideally this field is not that important, this should match the index of the element in the arrary */
        "It is running on the simulated enclave. Before providing you this service 0,\n\
we need to verify the following certified information:\n\
- Your date of birth\n\
- Your annual income\n\
- Your social security number\n\
\nYou need to provide the above-mentioned information to a trusted enclave which will process\n\
these information any will let us know your eligibility. We will use enclave(0) from the LibEnc\n\
for this purpose. Which is an enclave running on simulated SGX. Apart from this trusted enclave(0),\n\
none(including us) will be able to view your data. Even the trusted enclave will not be able to use\n\
the provided data after the expiry time specified by you. You can know about the details about\n\
enclave(0), directly from LibEnc.\n",/* Do not indent this or above lines */
        0 /* For simplicity, we are assuming service request x uses enclave x */
    },
    /* Assume the service 1 is: Personal loan providing service */
    {
        1, /* Ideally this field is not that important, this should match the index of the element in the arrary */
        "Before providing you this service 0, we need to verify the following certified information:\n\
- Your date of birth\n\
- Your social security number\n\
- Your annual income\n\
\nYou need to provide the above-mentioned information to a trusted enclave which will process\n\
these information any will let us know your eligibility. We will use enclave(1) from the LibEnc\n\
for this purpose. Apart from this trusted enclave(1), none(including us) will be able to view\n\
your data. Even the trusted enclave will not be able to use the provided data after the expiry\n\
time specified by you. You can know about the details about enclave(1), directly from LibEnc.  \n",/* Do not indent this or above lines */
        1 /* For simplicity, we are assuming service request x uses enclave x */
    },
    /* Assume the service 2 is: Car loan providing service */
    {
        2, /* Ideally this field is not that important, this should match the index of the element in the arrary */
        "Before providing you this service 1, we need to verify the following certified information:\n\
- Your date of birth\n\
- Your annual income\n\
- Your social security number\n\
- Driver's license issue date\n\
\nYou need to provide the above-mentioned information to a trusted enclave which will process\n\
these information any will let us know your eligibility. We will use enclave(2) from the LibEnc\n\
for this purpose. Apart from this trusted enclave(2), none(including us) will be able to view\n\
your data. Even the trusted enclave will not be able to use the provided data after the expiry\n\
time specified by you. You can know about the details about enclave(2), directly from LibEnc.  \n",/* Do not indent this or above lines */
        2 /* For simplicity, we are assuming service request x uses enclave x */
    }
};

#endif /* SR_BUSINESS_LOGIC_H */
