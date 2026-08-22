use serde::Deserialize;

pub const PROOF_VERSION_V2: &str = "2.0";

// Domain separation labels (CRYPTOGRAPHY.md §3)
pub const DOMAIN_EVIDENCE_V1: &[u8] = b"proofx/evidence/v1\x00";
pub const DOMAIN_LEAF_V2: &[u8] = b"proofx/leaf/v2\x00";
pub const DOMAIN_NODE_V2: &[u8] = b"proofx/node/v2\x00";
pub const DOMAIN_SIGN_V2: &[u8] = b"proofx/sign/v2\x00";

#[derive(Debug, Deserialize)]
pub struct Proof {
    #[serde(rename = "proofVersion")]
    pub proof_version: String,
    pub id: String,
    pub project: Project,
    pub subject: Subject,
    pub execution: Execution,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub relations: Vec<Relation>,
    #[serde(default)]
    pub claims: Vec<Claim>,
    pub binding: Binding,
    pub signature: Signature,
    #[serde(default)]
    pub coverage: Coverage,
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
    #[serde(default)]
    pub builder: Builder,
}

#[derive(Debug, Deserialize)]
pub struct Project {
    pub name: String,
    pub repository: String,
}

#[derive(Debug, Deserialize)]
pub struct Subject {
    pub commit: String,
    pub branch: String,
    pub repository: String,
}

#[derive(Debug, Deserialize)]
pub struct Execution {
    pub id: String,
    #[serde(rename = "type")]
    pub exec_type: String,
    #[serde(rename = "startedAt", default)]
    pub started_at: String,
    #[serde(rename = "completedAt", default)]
    pub completed_at: String,
    #[serde(default)]
    pub environment: Environment,
}

#[derive(Debug, Deserialize, Default)]
pub struct Environment {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub runtime: String,
}

#[derive(Debug, Deserialize)]
pub struct Evidence {
    pub id: String,
    #[serde(rename = "type", default)]
    pub evidence_type: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub timestamp: String,
    pub payload: String,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub struct Relation {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Claim {
    pub id: String,
    #[serde(rename = "type", default)]
    pub claim_type: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub statement: String,
    #[serde(default)]
    pub status: String,
    #[serde(rename = "supportedBy", default)]
    pub supported_by: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Binding {
    pub algorithm: String,
    pub root: String,
    #[serde(default)]
    pub entries: Vec<BindingEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BindingEntry {
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Coverage {
    #[serde(default)]
    pub evidence: CoverageDim,
    #[serde(default)]
    pub relations: CoverageDim,
    #[serde(default)]
    pub claims: CoverageDim,
    #[serde(default)]
    pub score: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct CoverageDim {
    #[serde(default)]
    pub total: u32,
    #[serde(default)]
    pub verified: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct Builder {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub host: String,
}
