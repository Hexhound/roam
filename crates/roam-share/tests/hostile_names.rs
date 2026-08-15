//! A share receiver writes files whose names a **stranger** chose. These assert
//! the names that must never survive validation — and, critically, that they do
//! not survive arriving over the wire either.

use roam_share::name::NameError;
use roam_share::{FileMeta, Payload, RelPath, SafeName, ShareFrame, ShareOffer};
use std::path::Path;

#[test]
fn traversal_and_separator_names_are_refused() {
    for hostile in [
        "..",
        ".",
        "../etc/passwd",
        "a/b",
        // `\` is a separator on Windows, so a name that looks like one
        // component on Linux becomes two there.
        "a\\b",
        "..\\..\\Windows\\System32",
    ] {
        assert!(
            SafeName::new(hostile).is_err(),
            "SafeName accepted {hostile:?}"
        );
    }
}

#[test]
fn absolute_paths_are_refused() {
    for hostile in ["/etc/passwd", "\\\\server\\share", "C:/Windows/System32"] {
        assert!(
            RelPath::new(hostile).is_err(),
            "RelPath accepted absolute {hostile:?}"
        );
    }
}

#[test]
fn a_relative_path_can_never_escape_its_destination() {
    // Anything that parses must resolve inside the base, by construction.
    let base = Path::new("/downloads");
    let path = RelPath::new("photos/holiday/beach.jpg").unwrap();
    let resolved = path.resolve_under(base);
    assert!(resolved.starts_with(base));
    assert_eq!(resolved, Path::new("/downloads/photos/holiday/beach.jpg"));

    // ...and the escaping form never parses in the first place.
    assert_eq!(
        RelPath::new("../../etc/passwd").unwrap_err(),
        NameError::DotSegment
    );
}

#[test]
fn names_that_disguise_themselves_are_refused() {
    // U+202E renders the rest right-to-left: this displays as "…annexe.png"
    // while actually ending in `.exe`. The user approves one thing, gets another.
    assert_eq!(
        SafeName::new("holiday\u{202E}gnp.exe").unwrap_err(),
        NameError::BidiOverride
    );
    // NUL truncates in C APIs, so this could be created as "safe.txt".
    assert_eq!(
        SafeName::new("safe.txt\0.exe").unwrap_err(),
        NameError::ControlCharacter
    );
    // Windows strips trailing dots/spaces, so this collides with "report.txt"
    // and could overwrite a file the user did not expect to be touched.
    assert_eq!(
        SafeName::new("report.txt ").unwrap_err(),
        NameError::TrailingDotOrSpace
    );
}

#[test]
fn windows_device_names_are_refused() {
    for hostile in ["CON", "nul", "COM1", "LPT9", "aux.txt"] {
        assert!(
            matches!(
                SafeName::new(hostile),
                Err(NameError::ReservedDeviceName(_))
            ),
            "SafeName accepted reserved {hostile:?}"
        );
    }
}

#[test]
fn ordinary_names_still_work() {
    // A validator that rejects everything would pass every test above.
    for ok in [
        "report.txt",
        "Ünïcodé fïle.pdf",
        "photo (1).jpeg",
        ".bashrc",
        "no-extension",
        "日本語.txt",
    ] {
        assert!(SafeName::new(ok).is_ok(), "SafeName rejected {ok:?}");
    }
    assert!(RelPath::new("a/b/c.txt").is_ok());
}

/// The one that actually matters: validation must happen on DECODE. A newtype
/// that only validates in its constructor is bypassed entirely by a peer that
/// sends an encoded frame, which is exactly how these names arrive.
#[test]
fn a_hostile_name_cannot_be_smuggled_in_through_the_wire_format() {
    // Build the malicious frame by encoding a struct with the same shape, so we
    // are decoding genuinely hostile bytes rather than something our own API
    // refused to construct.
    #[derive(serde::Serialize)]
    struct EvilMeta<'a> {
        path: &'a str,
        len: u64,
    }
    #[derive(serde::Serialize)]
    enum EvilPayload<'a> {
        File(EvilMeta<'a>),
    }
    #[derive(serde::Serialize)]
    struct EvilOffer<'a> {
        from: &'a str,
        items: Vec<EvilPayload<'a>>,
    }
    #[derive(serde::Serialize)]
    enum EvilFrame<'a> {
        Offer(EvilOffer<'a>),
    }

    let evil = EvilFrame::Offer(EvilOffer {
        from: "attacker",
        items: vec![EvilPayload::File(EvilMeta {
            path: "../../../../etc/cron.d/pwn",
            len: 10,
        })],
    });
    let bytes = postcard::to_stdvec(&evil).expect("encode hostile frame");

    assert!(
        ShareFrame::decode(&bytes).is_err(),
        "a path-traversal filename survived decoding"
    );
}

/// Same shape, but a legitimate path — proves the test above fails for the
/// right reason and not because the hand-rolled encoding is simply incompatible.
#[test]
fn the_smuggling_test_decodes_an_honest_frame_of_the_same_shape() {
    #[derive(serde::Serialize)]
    struct Meta<'a> {
        path: &'a str,
        len: u64,
    }
    #[derive(serde::Serialize)]
    enum P<'a> {
        File(Meta<'a>),
    }
    #[derive(serde::Serialize)]
    struct Offer<'a> {
        from: &'a str,
        items: Vec<P<'a>>,
    }
    #[derive(serde::Serialize)]
    enum F<'a> {
        Offer(Offer<'a>),
    }

    let honest = F::Offer(Offer {
        from: "phone",
        items: vec![P::File(Meta {
            path: "docs/notes.txt",
            len: 10,
        })],
    });
    let bytes = postcard::to_stdvec(&honest).unwrap();
    let decoded = ShareFrame::decode(&bytes).expect("an honest frame must decode");
    assert_eq!(decoded.kind(), "Offer");
}

#[test]
fn frames_round_trip() {
    let offer = ShareOffer {
        from: "alice-laptop".into(),
        items: vec![
            Payload::File(FileMeta {
                path: RelPath::new("notes.txt").unwrap(),
                len: 12,
            }),
            Payload::Folder {
                name: SafeName::new("holiday").unwrap(),
                files: vec![FileMeta {
                    path: RelPath::new("beach.jpg").unwrap(),
                    len: 900,
                }],
            },
            Payload::Text("hello".into()),
        ],
    };
    for frame in [
        ShareFrame::Offer(offer.clone()),
        ShareFrame::Accept {
            streams: vec![0, 1],
        },
        ShareFrame::Decline,
        ShareFrame::Chunk {
            stream: 1,
            offset: 4096,
            bytes: vec![1, 2, 3],
        },
        ShareFrame::Done,
    ] {
        assert_eq!(ShareFrame::decode(&frame.encode()).unwrap(), frame);
    }
}

#[test]
fn folder_contents_land_inside_the_folder() {
    let offer = ShareOffer {
        from: "phone".into(),
        items: vec![
            Payload::Text("inline, no stream".into()),
            Payload::Folder {
                name: SafeName::new("holiday").unwrap(),
                files: vec![
                    FileMeta {
                        path: RelPath::new("beach.jpg").unwrap(),
                        len: 10,
                    },
                    FileMeta {
                        path: RelPath::new("raw/DSC_0001.arw").unwrap(),
                        len: 20,
                    },
                ],
            },
        ],
    };
    let streams = offer.streams();
    // Text contributes no stream, so indices come only from the folder.
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[0].path.to_string(), "holiday/beach.jpg");
    assert_eq!(streams[1].path.to_string(), "holiday/raw/DSC_0001.arw");
    assert_eq!(streams[0].item, 1, "stream must point back at its payload");
    assert_eq!(offer.total_len(), 30);
}

/// A hostile offer can claim `u64::MAX` per file. The total must not wrap into
/// a small, plausible-looking number that a size check would then wave through.
#[test]
fn an_absurd_claimed_size_saturates_rather_than_wrapping() {
    let offer = ShareOffer {
        from: "attacker".into(),
        items: vec![
            Payload::File(FileMeta {
                path: RelPath::new("a").unwrap(),
                len: u64::MAX,
            }),
            Payload::File(FileMeta {
                path: RelPath::new("b").unwrap(),
                len: u64::MAX,
            }),
        ],
    };
    assert_eq!(offer.total_len(), u64::MAX);
}
