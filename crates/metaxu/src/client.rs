//! Thin bridge client storage.

/// Thin client for sending typed Thumos task requests to the runtime boundary.
pub struct BridgeClient<T> /* kanon:ignore RUST/pub-visibility -- public API */ {
    pub(crate) transport: T,
}

#[cfg(test)]
mod tests {
    use compact_str::CompactString;
    use ulid::Ulid;

    use super::*;
    use crate::{
        BridgeTransport, Result,
        protocol::{
            Capability, CapabilityGrant, DeviceAction, DeviceIdentityRef, IdentityKind,
            TaskRequest, TaskResponse, TaskStatus, decode_request, encode_response,
        },
    };

    struct InMemoryRuntime {
        seen_request: Option<TaskRequest>,
    }

    impl InMemoryRuntime {
        fn new() -> Self {
            Self { seen_request: None }
        }
    }

    impl BridgeTransport for InMemoryRuntime {
        type Error = crate::Error;

        fn exchange(&mut self, request_frame: &[u8]) -> Result<Vec<u8>> {
            let request = decode_request(request_frame)?;
            let response = match &request {
                TaskRequest::SendSms { request_id, to, .. } => TaskResponse::accepted(
                    *request_id,
                    DeviceAction::SmsQueued {
                        runtime_ref: CompactString::from(format!("runtime-sms:{to}")),
                    },
                ),
                _ => TaskResponse::rejected(request.request_id(), "unsupported fake task"),
            };

            self.seen_request = Some(request);
            encode_response(&response)
        }
    }

    fn identity_ref() -> DeviceIdentityRef {
        DeviceIdentityRef::new(IdentityKind::Session, "session-device-ref", [7; 32])
    }

    #[test]
    fn sms_request_round_trips_through_in_memory_runtime() -> Result<(), crate::Error> {
        let request_id = Ulid::from_bytes([1; 16]);
        let request = TaskRequest::SendSms {
            request_id,
            identity: identity_ref(),
            grants: vec![CapabilityGrant::new(
                Capability::SmsSend,
                "policy",
                "grant-sms-1",
            )],
            to: "+15551234567".into(),
            body: "bridge test".into(),
        };

        let mut client = BridgeClient::new(InMemoryRuntime::new());
        let response = client.submit(&request)?;
        let runtime = client.into_transport();

        assert_eq!(runtime.seen_request, Some(request));
        assert_eq!(
            response,
            TaskResponse {
                request_id,
                status: TaskStatus::Accepted {
                    action: DeviceAction::SmsQueued {
                        runtime_ref: "runtime-sms:+15551234567".into(),
                    },
                },
            }
        );

        Ok(())
    }

    #[test]
    fn client_rejects_request_without_required_grant() {
        let request = TaskRequest::SendSms {
            request_id: Ulid::from_bytes([2; 16]),
            identity: identity_ref(),
            grants: vec![CapabilityGrant::new(
                Capability::ContactsRead,
                "policy",
                "grant-contact-1",
            )],
            to: "+15551234567".into(),
            body: "bridge test".into(),
        };

        let mut client = BridgeClient::new(InMemoryRuntime::new());
        let result = client.submit(&request);

        assert!(matches!(
            result,
            Err(crate::Error::MissingCapability {
                capability: Capability::SmsSend,
                ..
            })
        ));
    }

    struct MismatchedResponseRuntime;

    impl BridgeTransport for MismatchedResponseRuntime {
        type Error = crate::Error;

        fn exchange(&mut self, request_frame: &[u8]) -> Result<Vec<u8>> {
            let _request = decode_request(request_frame)?;
            let response = TaskResponse::accepted(Ulid::from_bytes([99; 16]), DeviceAction::None);
            encode_response(&response)
        }
    }

    #[test]
    fn client_reports_response_request_mismatch() {
        let request_id = Ulid::from_bytes([3; 16]);
        let request = TaskRequest::SendSms {
            request_id,
            identity: identity_ref(),
            grants: vec![CapabilityGrant::new(
                Capability::SmsSend,
                "policy",
                "grant-sms-2",
            )],
            to: "+15550001111".into(),
            body: "mismatch test".into(),
        };

        let mut client = BridgeClient::new(MismatchedResponseRuntime);
        let result = client.submit(&request);

        assert!(matches!(
            result,
            Err(crate::Error::ResponseRequestMismatch { response_id, .. })
                if response_id == Ulid::from_bytes([99; 16])
        ));
    }
}
