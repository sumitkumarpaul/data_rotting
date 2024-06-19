#ifndef DATA_ISSUER_PUBKEY_H
#define DATA_ISSUER_PUBKEY_H


/* This file can be generated by the openssl tool, by using the command: openssl x509 -in sample_di_cert.pem -noout -C */
/* Note, if the credential of data-issuer is modified, then this file is to be updated accordingly */


/*
 * Subject: C = XY, ST = Some-state, L = Some-locality, O = Trusted organization, CN = Trusted-data-issuer
 * Issuer:  C = XY, ST = Some-state, L = Some-locality, O = Trusted organization, CN = Trusted-data-issuer
 */
unsigned char g_di_subject_name[121] = {
    0x30, 0x77, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x58, 0x59, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65,
    0x2D, 0x73, 0x74, 0x61, 0x74, 0x65, 0x31, 0x16, 0x30, 0x14,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0D, 0x53, 0x6F, 0x6D,
    0x65, 0x2D, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79,
    0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C,
    0x14, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x6F,
    0x72, 0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F,
    0x6E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x13, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x2D,
    0x64, 0x61, 0x74, 0x61, 0x2D, 0x69, 0x73, 0x73, 0x75, 0x65,
    0x72
};
unsigned char g_di_public_key[422] = {
    0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 
    0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 
    0x01, 0x81, 0x00, 0xA3, 0x6A, 0x02, 0x9F, 0xE8, 0x4F, 0xEF, 
    0x36, 0x67, 0x4F, 0xCF, 0xB7, 0xD9, 0x55, 0xF7, 0xA2, 0xED, 
    0xE4, 0xE8, 0x68, 0x81, 0x7D, 0x71, 0x02, 0x21, 0xBB, 0x47, 
    0x46, 0x59, 0x9E, 0xFA, 0x39, 0x51, 0xF8, 0x35, 0x0E, 0x09, 
    0x96, 0xD1, 0x45, 0xF5, 0xF9, 0xAD, 0x09, 0x79, 0xD0, 0x2E, 
    0x91, 0x5C, 0xCF, 0x3D, 0x38, 0xB5, 0x28, 0x3C, 0x93, 0x89, 
    0x0C, 0x24, 0x87, 0x25, 0xCD, 0xD8, 0xE2, 0xB2, 0xF7, 0x84, 
    0x14, 0x6C, 0x5B, 0x5E, 0x08, 0x06, 0xED, 0x13, 0x7B, 0x0E, 
    0xAE, 0x25, 0xC9, 0x9D, 0xC7, 0x5C, 0x48, 0xF1, 0x7A, 0xD3, 
    0x3A, 0xE3, 0x49, 0x57, 0xAC, 0xB4, 0xE5, 0xAC, 0xC0, 0xDF, 
    0x77, 0x75, 0xF8, 0x36, 0x53, 0x94, 0xE1, 0x67, 0x5D, 0x4E, 
    0x15, 0x29, 0x0E, 0x49, 0xAF, 0xD3, 0x68, 0xAA, 0x67, 0xB6, 
    0x62, 0x6F, 0xA5, 0x71, 0x6D, 0x5C, 0x8B, 0x02, 0xC5, 0xA2, 
    0x9B, 0x01, 0x73, 0x93, 0xB3, 0x53, 0x83, 0xD2, 0xB1, 0xAF, 
    0x28, 0x5E, 0x46, 0x27, 0xA3, 0x50, 0xEE, 0x6B, 0xF3, 0xA5, 
    0x5C, 0x41, 0x6D, 0xA5, 0xAF, 0xD5, 0xD0, 0x33, 0x93, 0xFE, 
    0x0F, 0x20, 0xB4, 0x42, 0x06, 0xE3, 0x82, 0xFD, 0xB6, 0xE2, 
    0x23, 0x39, 0xFB, 0x21, 0x5E, 0xB4, 0x57, 0xDC, 0x95, 0x1F, 
    0x86, 0x8C, 0x3F, 0x67, 0x26, 0xE8, 0x9B, 0x76, 0xB0, 0x5B, 
    0xED, 0x4B, 0x9C, 0xAF, 0x33, 0xFB, 0xD3, 0xAF, 0x87, 0x4E, 
    0x7C, 0xC0, 0x4A, 0xEB, 0x16, 0xB9, 0x60, 0x3C, 0xFA, 0xB1, 
    0xBC, 0x03, 0xA5, 0x97, 0xB2, 0x07, 0x17, 0xA3, 0xB4, 0x0C, 
    0x52, 0xBC, 0x44, 0x23, 0xC3, 0x9B, 0xB4, 0x3E, 0x65, 0x54, 
    0x8B, 0x3F, 0x40, 0x01, 0xAD, 0x48, 0x9E, 0x92, 0x34, 0x86, 
    0xF9, 0x8C, 0x5D, 0x6D, 0x54, 0x7B, 0x79, 0x1E, 0xD2, 0xA4, 
    0xF1, 0xD0, 0x25, 0xCE, 0xE8, 0x57, 0xFC, 0x37, 0xC8, 0x95, 
    0x43, 0xF9, 0xB8, 0xDD, 0xFA, 0x61, 0xF2, 0x9D, 0x39, 0x99, 
    0x48, 0x36, 0x59, 0x1F, 0x3E, 0x5C, 0x84, 0x94, 0x2C, 0xEB, 
    0x8F, 0x25, 0xF8, 0xA5, 0xC2, 0x5A, 0xD7, 0xA0, 0xAE, 0xB6, 
    0x12, 0xCD, 0x15, 0xAB, 0x48, 0x51, 0x26, 0x20, 0xD7, 0x97, 
    0x12, 0xB9, 0x35, 0x51, 0xC1, 0x7F, 0x59, 0x3C, 0xEF, 0xF1, 
    0x52, 0x45, 0xFE, 0x2A, 0x5C, 0xC1, 0xFA, 0xA1, 0x95, 0x05, 
    0x64, 0x16, 0x0D, 0x60, 0x18, 0xE2, 0x8D, 0x0E, 0xD3, 0x71, 
    0x68, 0xAA, 0xCC, 0x75, 0xFF, 0x02, 0xCA, 0x81, 0xD4, 0x09, 
    0x5B, 0x0B, 0x3D, 0x7B, 0x8A, 0x7D, 0x06, 0x0A, 0xE2, 0x06, 
    0x3A, 0x5D, 0x91, 0xCB, 0x59, 0x19, 0xD5, 0xC8, 0x7B, 0x94, 
    0xD5, 0x23, 0xF8, 0x1E, 0x38, 0x90, 0xED, 0xCA, 0x24, 0xE4, 
    0xB5, 0x26, 0xE6, 0xC1, 0x4F, 0x0E, 0xBC, 0xE8, 0x40, 0x4F, 
    0xE4, 0xC5, 0xB3, 0x05, 0xA3, 0xEF, 0x59, 0x02, 0x03, 0x01, 
    0x00, 0x01
};
unsigned char g_di_certificate[1235] = {
    0x30, 0x82, 0x04, 0xCF, 0x30, 0x82, 0x03, 0x37, 0xA0, 0x03, 
    0x02, 0x01, 0x02, 0x02, 0x14, 0x54, 0xD6, 0x1F, 0xFD, 0x3B, 
    0xB4, 0x26, 0x00, 0x19, 0x47, 0xFD, 0x68, 0xB3, 0xB4, 0x96, 
    0xF3, 0xED, 0xF6, 0x9C, 0x17, 0x30, 0x0D, 0x06, 0x09, 0x2A, 
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 
    0x30, 0x77, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 
    0x06, 0x13, 0x02, 0x58, 0x59, 0x31, 0x13, 0x30, 0x11, 0x06, 
    0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 
    0x2D, 0x73, 0x74, 0x61, 0x74, 0x65, 0x31, 0x16, 0x30, 0x14, 
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0D, 0x53, 0x6F, 0x6D, 
    0x65, 0x2D, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79, 
    0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 
    0x14, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x6F, 
    0x72, 0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 
    0x6E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 
    0x0C, 0x13, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x2D, 
    0x64, 0x61, 0x74, 0x61, 0x2D, 0x69, 0x73, 0x73, 0x75, 0x65, 
    0x72, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x31, 0x31, 
    0x38, 0x31, 0x38, 0x35, 0x38, 0x33, 0x33, 0x5A, 0x17, 0x0D, 
    0x33, 0x33, 0x30, 0x31, 0x31, 0x35, 0x31, 0x38, 0x35, 0x38, 
    0x33, 0x33, 0x5A, 0x30, 0x77, 0x31, 0x0B, 0x30, 0x09, 0x06, 
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x58, 0x59, 0x31, 0x13, 
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 
    0x6F, 0x6D, 0x65, 0x2D, 0x73, 0x74, 0x61, 0x74, 0x65, 0x31, 
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0D, 
    0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 
    0x69, 0x74, 0x79, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 
    0x04, 0x0A, 0x0C, 0x14, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 
    0x64, 0x20, 0x6F, 0x72, 0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 
    0x74, 0x69, 0x6F, 0x6E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 
    0x55, 0x04, 0x03, 0x0C, 0x13, 0x54, 0x72, 0x75, 0x73, 0x74, 
    0x65, 0x64, 0x2D, 0x64, 0x61, 0x74, 0x61, 0x2D, 0x69, 0x73, 
    0x73, 0x75, 0x65, 0x72, 0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 
    0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xA3, 0x6A, 0x02, 
    0x9F, 0xE8, 0x4F, 0xEF, 0x36, 0x67, 0x4F, 0xCF, 0xB7, 0xD9, 
    0x55, 0xF7, 0xA2, 0xED, 0xE4, 0xE8, 0x68, 0x81, 0x7D, 0x71, 
    0x02, 0x21, 0xBB, 0x47, 0x46, 0x59, 0x9E, 0xFA, 0x39, 0x51, 
    0xF8, 0x35, 0x0E, 0x09, 0x96, 0xD1, 0x45, 0xF5, 0xF9, 0xAD, 
    0x09, 0x79, 0xD0, 0x2E, 0x91, 0x5C, 0xCF, 0x3D, 0x38, 0xB5, 
    0x28, 0x3C, 0x93, 0x89, 0x0C, 0x24, 0x87, 0x25, 0xCD, 0xD8, 
    0xE2, 0xB2, 0xF7, 0x84, 0x14, 0x6C, 0x5B, 0x5E, 0x08, 0x06, 
    0xED, 0x13, 0x7B, 0x0E, 0xAE, 0x25, 0xC9, 0x9D, 0xC7, 0x5C, 
    0x48, 0xF1, 0x7A, 0xD3, 0x3A, 0xE3, 0x49, 0x57, 0xAC, 0xB4, 
    0xE5, 0xAC, 0xC0, 0xDF, 0x77, 0x75, 0xF8, 0x36, 0x53, 0x94, 
    0xE1, 0x67, 0x5D, 0x4E, 0x15, 0x29, 0x0E, 0x49, 0xAF, 0xD3, 
    0x68, 0xAA, 0x67, 0xB6, 0x62, 0x6F, 0xA5, 0x71, 0x6D, 0x5C, 
    0x8B, 0x02, 0xC5, 0xA2, 0x9B, 0x01, 0x73, 0x93, 0xB3, 0x53, 
    0x83, 0xD2, 0xB1, 0xAF, 0x28, 0x5E, 0x46, 0x27, 0xA3, 0x50, 
    0xEE, 0x6B, 0xF3, 0xA5, 0x5C, 0x41, 0x6D, 0xA5, 0xAF, 0xD5, 
    0xD0, 0x33, 0x93, 0xFE, 0x0F, 0x20, 0xB4, 0x42, 0x06, 0xE3, 
    0x82, 0xFD, 0xB6, 0xE2, 0x23, 0x39, 0xFB, 0x21, 0x5E, 0xB4, 
    0x57, 0xDC, 0x95, 0x1F, 0x86, 0x8C, 0x3F, 0x67, 0x26, 0xE8, 
    0x9B, 0x76, 0xB0, 0x5B, 0xED, 0x4B, 0x9C, 0xAF, 0x33, 0xFB, 
    0xD3, 0xAF, 0x87, 0x4E, 0x7C, 0xC0, 0x4A, 0xEB, 0x16, 0xB9, 
    0x60, 0x3C, 0xFA, 0xB1, 0xBC, 0x03, 0xA5, 0x97, 0xB2, 0x07, 
    0x17, 0xA3, 0xB4, 0x0C, 0x52, 0xBC, 0x44, 0x23, 0xC3, 0x9B, 
    0xB4, 0x3E, 0x65, 0x54, 0x8B, 0x3F, 0x40, 0x01, 0xAD, 0x48, 
    0x9E, 0x92, 0x34, 0x86, 0xF9, 0x8C, 0x5D, 0x6D, 0x54, 0x7B, 
    0x79, 0x1E, 0xD2, 0xA4, 0xF1, 0xD0, 0x25, 0xCE, 0xE8, 0x57, 
    0xFC, 0x37, 0xC8, 0x95, 0x43, 0xF9, 0xB8, 0xDD, 0xFA, 0x61, 
    0xF2, 0x9D, 0x39, 0x99, 0x48, 0x36, 0x59, 0x1F, 0x3E, 0x5C, 
    0x84, 0x94, 0x2C, 0xEB, 0x8F, 0x25, 0xF8, 0xA5, 0xC2, 0x5A, 
    0xD7, 0xA0, 0xAE, 0xB6, 0x12, 0xCD, 0x15, 0xAB, 0x48, 0x51, 
    0x26, 0x20, 0xD7, 0x97, 0x12, 0xB9, 0x35, 0x51, 0xC1, 0x7F, 
    0x59, 0x3C, 0xEF, 0xF1, 0x52, 0x45, 0xFE, 0x2A, 0x5C, 0xC1, 
    0xFA, 0xA1, 0x95, 0x05, 0x64, 0x16, 0x0D, 0x60, 0x18, 0xE2, 
    0x8D, 0x0E, 0xD3, 0x71, 0x68, 0xAA, 0xCC, 0x75, 0xFF, 0x02, 
    0xCA, 0x81, 0xD4, 0x09, 0x5B, 0x0B, 0x3D, 0x7B, 0x8A, 0x7D, 
    0x06, 0x0A, 0xE2, 0x06, 0x3A, 0x5D, 0x91, 0xCB, 0x59, 0x19, 
    0xD5, 0xC8, 0x7B, 0x94, 0xD5, 0x23, 0xF8, 0x1E, 0x38, 0x90, 
    0xED, 0xCA, 0x24, 0xE4, 0xB5, 0x26, 0xE6, 0xC1, 0x4F, 0x0E, 
    0xBC, 0xE8, 0x40, 0x4F, 0xE4, 0xC5, 0xB3, 0x05, 0xA3, 0xEF, 
    0x59, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 
    0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 
    0x14, 0x3B, 0xFF, 0x5F, 0x5B, 0xB7, 0x54, 0xF7, 0xDD, 0x31, 
    0x70, 0x8D, 0x88, 0x4C, 0xA1, 0xFB, 0x40, 0x3D, 0xD3, 0x2A, 
    0x7D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 
    0x30, 0x16, 0x80, 0x14, 0x3B, 0xFF, 0x5F, 0x5B, 0xB7, 0x54, 
    0xF7, 0xDD, 0x31, 0x70, 0x8D, 0x88, 0x4C, 0xA1, 0xFB, 0x40, 
    0x3D, 0xD3, 0x2A, 0x7D, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 
    0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 
    0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 
    0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x81, 
    0x00, 0x96, 0x21, 0x3D, 0x4B, 0xA7, 0x0A, 0x7E, 0x01, 0xB8, 
    0xEF, 0xCB, 0x11, 0x8D, 0x3B, 0xD6, 0xA2, 0x17, 0x95, 0xF8, 
    0x6E, 0x1C, 0x75, 0x32, 0xDA, 0xD7, 0xC3, 0xED, 0xA9, 0xED, 
    0x75, 0x30, 0x20, 0x9E, 0x28, 0x3C, 0xCE, 0xCD, 0xD3, 0x7B, 
    0x5D, 0x41, 0x2C, 0x41, 0x79, 0xD7, 0x2A, 0xB5, 0xEC, 0x28, 
    0xFE, 0xD5, 0x50, 0x12, 0xD2, 0x9A, 0xCB, 0xD1, 0xF2, 0x52, 
    0x65, 0x2A, 0x97, 0xC4, 0xDE, 0x7F, 0x07, 0xF0, 0xA6, 0xA1, 
    0x88, 0xFC, 0xC0, 0xCD, 0xD0, 0xC0, 0xA1, 0x98, 0x94, 0xCC, 
    0x80, 0x4F, 0x33, 0x8B, 0x13, 0xDF, 0x2E, 0x89, 0x44, 0x3E, 
    0xB6, 0xCC, 0x2C, 0x84, 0x55, 0xB4, 0x0B, 0x8E, 0xD2, 0x84, 
    0x51, 0xB9, 0x30, 0xBB, 0x2A, 0x5A, 0x2B, 0x65, 0x2F, 0x82, 
    0x67, 0x00, 0xB2, 0x3C, 0xBF, 0xFA, 0x99, 0xE4, 0xD3, 0xDB, 
    0x83, 0x4D, 0x01, 0x9A, 0xC5, 0x5A, 0xE2, 0x54, 0xFB, 0xA3, 
    0x9A, 0x6B, 0xB6, 0x6A, 0xB7, 0x93, 0x68, 0x2A, 0xC7, 0x10, 
    0x5C, 0xD6, 0x01, 0xF8, 0x99, 0xBF, 0x21, 0x58, 0xF9, 0xA0, 
    0xF4, 0x9D, 0x33, 0x0F, 0x04, 0x70, 0x94, 0x21, 0x3A, 0xCA, 
    0x0C, 0x6A, 0x9B, 0x1F, 0xBF, 0xEA, 0xA0, 0x74, 0x92, 0x22, 
    0x76, 0x8F, 0x83, 0x8E, 0x20, 0x58, 0x78, 0xF9, 0x56, 0x0C, 
    0x1C, 0x4F, 0x48, 0x71, 0x1F, 0x0E, 0x21, 0xAB, 0x62, 0x1F, 
    0xD3, 0x39, 0xCC, 0x19, 0x17, 0x13, 0x58, 0xCD, 0x0D, 0xFA, 
    0x2E, 0x04, 0x38, 0x3A, 0x50, 0xD8, 0x88, 0x6A, 0x52, 0x80, 
    0x89, 0xD3, 0x2F, 0x0E, 0x15, 0xFA, 0x40, 0x35, 0xCC, 0x8F, 
    0x0E, 0xD0, 0x5A, 0x91, 0xB2, 0x44, 0x59, 0xA4, 0x2B, 0xA0, 
    0x4B, 0x7C, 0x76, 0x5A, 0x7E, 0x22, 0x8E, 0xE7, 0x59, 0x9D, 
    0xA5, 0x41, 0x9D, 0x7C, 0x94, 0x6B, 0xCD, 0xEC, 0xB7, 0x32, 
    0x94, 0x7B, 0x30, 0x11, 0xD1, 0xC6, 0x98, 0xB6, 0x7C, 0xE1, 
    0x6C, 0xC8, 0x38, 0x3F, 0xE8, 0xE9, 0x16, 0x33, 0x09, 0x25, 
    0x8A, 0x05, 0x54, 0x1C, 0x9B, 0xCA, 0x66, 0x9B, 0x0F, 0x26, 
    0x0F, 0x1C, 0x4D, 0x2D, 0x8F, 0x0C, 0xA6, 0x01, 0x9C, 0x53, 
    0xCE, 0x97, 0xCB, 0xF9, 0x30, 0xEC, 0x53, 0x5D, 0xAE, 0x32, 
    0xB7, 0x2B, 0x4C, 0x69, 0x92, 0xFD, 0x67, 0xAB, 0x35, 0x72, 
    0xDF, 0xBD, 0x46, 0x29, 0xCF, 0x67, 0x19, 0xCA, 0x1F, 0x4B, 
    0x1A, 0x70, 0xE6, 0x9A, 0xEB, 0xF0, 0x84, 0x80, 0x42, 0xA5, 
    0x86, 0xE7, 0xD5, 0x4F, 0xB6, 0x48, 0xB4, 0xBD, 0x4B, 0xCD, 
    0x6D, 0xD5, 0x25, 0xC6, 0x82, 0x5F, 0x4F, 0xAE, 0xF7, 0x70, 
    0x1A, 0x25, 0x30, 0xCA, 0x99, 0x42, 0x4E, 0x88, 0x5C, 0x43, 
    0x84, 0xD4, 0x6D, 0x57, 0xF5, 0x03, 0xFD, 0x46, 0x9F, 0x20, 
    0xB2, 0x8F, 0x7D, 0x6C, 0x94, 0x48, 0xF6, 0x43, 0x28, 0x47, 
    0xA3, 0x8A, 0x84, 0xAA, 0xBE
};

#endif /* DATA_ISSUER_PUBKEY_H */
