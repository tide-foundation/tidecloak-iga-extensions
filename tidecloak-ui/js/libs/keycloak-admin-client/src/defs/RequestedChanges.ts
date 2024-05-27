import type RequestChangesUserRecord from "./RequestChangesUserRecord.js";
export default interface RequestedChanges {
    action: string;
    changeSetType: string;
    requestType: string;
    clientId: string;
    actionType: string;
    draftRecordId: string;
    userRecord: RequestChangesUserRecord[];
    status: string;
}

