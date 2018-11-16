/**
 * This file is a part of Qosmos Device Identification SDK
 * Copyright Qosmos Tech 2000-2018 - All rights reserved.
 * This computer program and all its components are protected by authors' rights
 * and copyright law and by international treaties.
 * Any representation, reproduction, distribution or modification of this
 * program or any portion of it is forbidden without Qosmos' explicit and
 * written agreement and may result in severe civil and criminal penalties, and
 * will be prosecuted to the maximum extent possible under the law.
 */
#ifndef __QMDEVICE_H_
#define __QMDEVICE_H_

#include <stdint.h>

#define ETH_ADDRESS_LEN 6

/**
 * @enum error codes
 */
enum qmdev_error {
    QMDEV_SUCCESS = 0,
    QMDEV_INVALID_ARGUMENT  = -1,
    QMDEV_NOT_ENOUGH_MEMORY  = -2,
    QMDEV_NO_DEVICE_CONTEXT_AVAILABLE = -3,
    QMDEV_RE_INIT_FAILED  = -4,
    QMDEV_RE_INJECTION_FAILED = -5,
    QMDEV_DEVICE_RESULT_NB_EXCEEDED = -6,
    QMDEV_RE_CTX_DESTRUCTION_FAILED = -7,
    QMDEV_RE_CTX_RESET_FAILED = -8,
    QMDEV_RE_DESTRUCTION_FAILED = -9
};

/**
 * @enum device result flags
 */
enum qmdev_result_flags_value {
    QMDEV_RESULT_HAS_CHANGED =       1 << 0,
    QMDEV_RESULT_SCORE_HAS_CHANGED = 1 << 1
};

/**
 * @enum device metadata identifiers
 */
enum qmdev_metadata_identifier {
    QMDEV_VENDOR = 0,
    QMDEV_MODEL = 1,
    QMDEV_TYPE = 2,
    QMDEV_OS_VENDOR = 3,
    QMDEV_OS = 4,
    QMDEV_OS_VERSION = 5,
    QMDEV_NIC_VENDOR = 6,
};
#define QMDEV_MAX_METADATA_ID 7

/**
 * @enum device fingerprint copy types
 */
enum qmdev_fingerprint_copy {
    QMDEV_SHALLOW_COPY   = 0,
    QMDEV_DEEP_COPY      = 1,
};

/**
 * @enum fingerprint counter types
 */
enum qmdev_fingerprint_counter_type {
    QMDEV_NB_INJECTED_FINGERPRINTS = 0,
    QMDEV_NB_MATCHED_FINGERPRINTS,
};

/**
 * Library instance
 * High-level opaque object required to use the library.
 */
struct qmdev_instance;

/**
 * Device context
 * An object corresponding to the definition of a device.
 */
struct qmdev_device_context;

struct qmdev_fingerprint;
struct qmdev_fingerprint_group;

struct qmdev_result;
struct qmdev_result_device;

/**
 * @brief  Creates a new device identification instance.
 * @param [in] conf  library instance configuration.
 * @param [out]  instance  an instance of the library created according to conf.
 *
 * @return One of the following codes:
 * - QMDEV_SUCCESS: success
 * - QMDEV_INVALID_ARGUMENT: invalid parameter(s) or invalid configuration
 * - QMDEV_NOT_ENOUGH_MEMORY: no memory available
 * - QMDEV_RE_INIT_FAILED: unable to initialize rule engine
 *
 * @note Configuration must contains the following fields:
 * - nb_device_contexts: maximum number of devices for this instance (minimum 1, maximum 2^31).
 * - nb_devices_per_result: number of devices a result can contain. (minimum 1, maximum 127).
 * - nb_unmatched_fingerprints_per_device: number of unmatched fingerprints stored before logging. (minimum 1, maximum 2^31).
 *
 * #### Example ####
 * "nb_device_contexts=1000;nb_devices_per_result=5;nb_unmatched_fingerprints_per_device=5"
 */
int qmdev_instance_create(const char *conf, struct qmdev_instance **instance);

/**
 * @brief         Destroys a device identification instance
 * @param [in]    instance    an instance of the library.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid instance.
 */
int qmdev_instance_destroy(struct qmdev_instance *instance);

/**
 * @brief         Returns the library instance version.
 * @param [in]    instance an instance of the library.
 * @param [out]   version pointer to the version string.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid parameter(s) or instance.
 */
int qmdev_instance_version_get_string(struct qmdev_instance *instance,
                                      const char **version);


/**
 * @brief         Creates a device context
 * @param [in]    instance        an instance of the library.
 * @param [out]   device_context  an object abstracting a device.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid parameter(s) or instance.
 * - QMDEV_NO_DEVICE_CONTEXT_AVAILABLE: no device context available.
 */
int qmdev_device_context_create(struct qmdev_instance        *instance,
                                struct qmdev_device_context **device_context);

/**
 * @brief         Destroys a device context
 * @note          Upon destruction device_context no longer points to a valid object.
 * @param [in]    device_context  an object abstracting a device.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context.
 *
 * @warning       This function is not thread-safe.
 */
int qmdev_device_context_destroy(struct qmdev_device_context *device_context);

/**
 * @brief        Resets a device_context.
 * Clears all the data associated with the object.
 *
 * @param [in]    device_context an object abstracting a device.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context.
 *
 *  @warning        This function is not thread-safe.
 */
int qmdev_device_context_reset(struct qmdev_device_context *device_context);

/**
 * @brief         Gets the library instance related to the device context.
 * @param [in]   device_context  an object abstracting a device.
 * @param [out]  instance        the library instance containing device_context.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context or instance.
 */
int qmdev_device_context_instance_get(struct qmdev_device_context
                                      *device_context,
                                      struct qmdev_instance       **instance);

/**
 * @brief        Gets the user handle attached to a device context.
 * @param [in]    device_context  an object abstracting a device.
 * @param [in]    user_handle a pointer to user data.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context.
 */
int qmdev_device_context_user_handle_set(struct qmdev_device_context
        *device_context,
        void                         *user_handle);

/**
 * @brief       Sets the user handle to a device context.
 * @param [in]  device_context  an object abstracting a device.
 * @param [out] user_handle a pointer to user data.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context or user handle.
 */
int qmdev_device_context_user_handle_get(struct qmdev_device_context
        *device_context,
        void                        **user_handle);
/**
 * @brief         Creates a fingerprint group
 * @param [in]    device_context  an object abstracting a device.
 * @param [out]   fp_group        pointer to an instance of a fingerprint group.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid device context or fp_group.
 * - QMDEV_NOT_ENOUGH_MEMORY: no memory available.
 */
int qmdev_fingerprint_group_create(struct qmdev_device_context
                                   *device_context,
                                   struct qmdev_fingerprint_group **fp_group);

/**
 * @brief       Destroys a fingerprint group.
 * @details     Frees all memory allocated for the group and fingerprints if any.
 * @param [in]  fp_group  pointer to an instance of a fingerprint group.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid fp_group.
 */
int qmdev_fingerprint_group_destroy(struct qmdev_fingerprint_group *fp_group);

/**
 * @brief     Resets a fingerprint group.
 * @details   Frees fingerprints allocated for the group if any.
 * The group can then be reused for the same device_context.
 * @param [in]    fp_group  pointer to an instance of a fingerprint group.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS:          success.
 * - QMDEV_INVALID_ARGUMENT: invalid fp_group.
 */
int qmdev_fingerprint_group_reset(struct qmdev_fingerprint_group *fp_group);


/**
 * @brief       Gets device context from the fingerprint group.
 * @param [in]  fp_group  pointer to an instance of a fingerprint group.
 * @param [out] device_context pointer to the device_context instance the group belongs to.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS:          success.
 * - QMDEV_INVALID_ARGUMENT: invalid fp_group or device_context.
 */
int qmdev_fingerprint_group_device_context_get(struct qmdev_fingerprint_group
        *fp_group,
        struct qmdev_device_context    **device_context);

/**
 * @brief    Add a fingerprint to a fingerprint group.
 * @note    There are two kinds of attributes:
 * - Attributes directly provided by the Protocol Bundle:
 *    - http:user_agent(Q_HTTP_USER_AGENT)
 *    - dhcp:host_name(Q_DHCP_HOST_NAME)
 *    - http_proxy:user_agent(Q_HTTP_PROXY_USER_AGENT)
 *    - dhcp:chaddr(Q_DHCP_CHADDR)
 *    .
 * - Attributes to be provided by the application using the ixEngine and the Protocol Bundle:
 *    - tcp:window(Q_TCP_WINDOW)
 *    - eth:address(Q_ETH_ADDRESS)
 *    - tcp:header_options(Q_TCP_HEADER_OPTIONS)
 *    - dhcp_parameter_request_list(Q_DHCP_PARAMETER_REQUEST_LIST)
 *    - dhcp_vendor_class_identifier(Q_DHCP_VENDOR_CLASS_IDENTIFIER)
 *    .
 * .
 *
 * @param [in]   fp_group         pointer to an instance of a fingerprint group.
 * @param [in]   deep_copy        0: copy data, or 1: allocate memory and copy data.
 * @param [in]   proto_id         protocol id of the fingerprint.
 * @param [in]   attr_id          attribute id of the fingerprint.
 * @param [in]   attr_value       attribute value.
 * @param [in]   attr_value_len   attribute value len.
 * @param [in]   attr_flags       attribute flags.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: invalid fp_group, proto_id, attr_id, attr_value, or attr_value_len
 */
int qmdev_fingerprint_set(struct qmdev_fingerprint_group  *fp_group,
                          unsigned int                     deep_copy,
                          unsigned int                     proto_id,
                          unsigned int                     attr_id,
                          unsigned int                     attr_flags,
                          unsigned int                     attr_value_len,
                          const char                      *attr_value);

/**
 * @brief     Process a fingerprint group
 * @details   Fingerprints of a given Fingerprint Group are each processed
 * independently by the libqmdevice instance to obtain an intermediary result,
 * which is then integrated into the "global result" (qmdev_result) stored in
 * the corresponding device context
 * (note: this "global result" may represent more than one device).
 *
 * @param [in]  fp_group fingerprint group to process.
 * @param [out] result   object containing results (device identification info).
 * @param [out] result_flags    set on device information changes (QMDEV_RESULT_HAS_CHANGED, QMDEV_RESULT_SCORE_HAS_CHANGED).
 *
 * @return        One of the following codes:
 * - QMDEV_SUCCESS:                success.
 * - QMDEV_INVALID_ARGUMENT:       result or flags are null.
 * - QMDEV_RE_INJECTION_FAILED:    rule engine injection failed.
 * - QMDEV_DEVICE_RESULT_EXCEEDED: maximum number of devices allocated exceeded.
 */
int qmdev_device_process(struct qmdev_fingerprint_group    *fp_group,
                         struct qmdev_result              **result,
                         unsigned int                      *result_flags);


/**
 * @brief   Retrieve device identification information from result.
 * @details A result can contain multiple devices, i.e. candidates.
 * Each candidate has a score expressed as a percentage based on the number of fingerprint matches.
 * First call should be made with *device set to NULL.
 * If *device is equal to NULL, it means no more devices were found.
 *
 * @param [in]  result       object containing devices information and returned by qmdev_device_process().
 * @param [out] device       device candidate containing device metadata.
 * @param [out] score        device score (percentage).
 * @param [out] device_flags device flags
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: result, device, score or device_flags are null.
 */
int qmdev_result_device_get_next(struct qmdev_result         *result,
                                 struct qmdev_result_device **device,
                                 unsigned int                *score,
                                 unsigned int                *device_flags);

/**
 * @brief   Get metadata from a device result.
 * @param [in] device               device candidate containing device metadata.
 * @param [in] metadata_id          device metadata identifier.
 * @param [out] metadata_value_id   device metadata value identifier:
 * - For os version, it is always zero.
 * - For all other device metadata, zero means there is no id for this metadata.
 * @param [out] metadata_value      device metadata value.
 * @param [out] metadata_value_len  length of device metadata value.
 * @param [out] metadata_flags      device candidate containing device metadata flags.
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: device is null or metadata_id is incorrect.
 */
int qmdev_result_device_metadata_get(struct qmdev_result_device  *device,
                                     unsigned int                 metadata_id,
                                     unsigned int                *metadata_value_id,
                                     const char                 **metadata_value,
                                     unsigned int                *metadata_value_len,
                                     unsigned int                *metadata_flags);

/**
 * @brief   Get context from result.
 *
 * @param [in] result           object containing devices information.
 * @param [out] device_context  pointer address to it associated device_context.
 *
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: result or device_context are null.
 *
 */
int qmdev_result_device_context_get(struct qmdev_result         *result,
                                    struct qmdev_device_context **device_context);

/**
 * @brief   Get number of processed fingerprints for a device_context.
 *
 * @details This function gets a counter value for a fingerprint depending on
 * protocol, attribute id and a counter type.
 * If proto_id and attr_id are both set to 0 then it returns the total count.
 *
 * @param [in] device_context              device_context object to use.
 * @param [in] proto_id                    fingerprint protocol id.
 * @param [in] attr_id                     fingerprint attribute id.
 * @param [in] fingerprint_counter_id      fingerprint counter id.
 * @param [out] fingerprint_counter_value  counter value.
 *
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: device_context or fingerprint_counter_value are
 * null or proto_id or fingerprint_counter_id are not valid.
 */
int qmdev_device_context_fingerprint_get_count(struct qmdev_device_context
        *device_context,
        unsigned int                  proto_id,
        unsigned int                  attr_id,
        unsigned int                  fingerprint_counter_id,
        unsigned int                 *fingerprint_counter_value);
/**
 * @brief   Get error string for the specified error code.
 * @param [in] error the error code (returned by the library) to translate.
 * @return  the string corresponding to the error code.
 */

const char *qmdev_error_get_string(int error);

/**
 * @brief   Get metadata string for the specified device metadata identifier.
 *
 * @param [in] device_metadata_id              device metadata identifier.
 * @param [in] device_metadata_value           device metadata value.
 * @param [out] device_metadata_str_value      metadata string corresponding to the given device metadata value.
 * @param [out] device_metadata_str_value_len  metadata string length.
 *
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: device_metadata_value or device_metadata_value_len
 * is null, or device_metadata_value_id is out of boundaries.
 */

int qmdev_device_metadata_get_byid(enum qmdev_metadata_identifier
                                   device_metadata_id,
                                   unsigned int                   device_metadata_value,
                                   char const                   **device_metadata_str_value,
                                   unsigned int                  *device_metadata_str_value_len);
/**
 * @brief       Output function invoked by the
 * Unmatched Device Fingerprint Logger.
 *
 * @param [out] output pointer to output buffer
 * @param [in]  format formatted output string (printf style)
 *
 * @return     defined by the function
 */
typedef int (*qmdev_output_fn_t)(void *output, const char *format, ...);


/**
 * @brief Set the output buffer and the output function to be used by the
 * Unmatched Device Fingerprint Logger.
 *
 * @param    instance  an instance of the libqmdevice library.
 * @param    output    pointer to output buffer.
 * @param    output_fn output function.
 *
 * @return        One of the following codes:
 * - QMDEV_SUCCESS: success.
 * - QMDEV_INVALID_ARGUMENT: instance is invalid or output_fn is null.
 */

int qmdev_instance_logger_dump_info_set(struct qmdev_instance *instance,
                                        void *output, qmdev_output_fn_t output_fn);

#endif /* __QMDEVICE_H_ */
