import type RequestChangesUserRecord from "./RequestChangesUserRecord.js";
export default interface RequestedChanges {
    type: string;
    parentRecordId: string;
    userRecord: RequestChangesUserRecord[];
    description: string;
}

