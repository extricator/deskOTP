export namespace entries {
	
	export class CodePayload {
	    id: string;
	    code: string;
	    remaining: number;
	    period: number;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new CodePayload(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.code = source["code"];
	        this.remaining = source["remaining"];
	        this.period = source["period"];
	        this.type = source["type"];
	    }
	}
	export class EntryDetails {
	    id: string;
	    name: string;
	    issuer: string;
	    group: string;
	    note: string;
	    secret: string;
	    type: string;
	    algo: string;
	    period: number;
	    digits: number;
	    icon: string;
	    usageCount: number;
	
	    static createFrom(source: any = {}) {
	        return new EntryDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.issuer = source["issuer"];
	        this.group = source["group"];
	        this.note = source["note"];
	        this.secret = source["secret"];
	        this.type = source["type"];
	        this.algo = source["algo"];
	        this.period = source["period"];
	        this.digits = source["digits"];
	        this.icon = source["icon"];
	        this.usageCount = source["usageCount"];
	    }
	}
	export class EntryMetadata {
	    id: string;
	    name: string;
	    issuer: string;
	    group: string;
	    icon: string;
	    usageCount: number;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new EntryMetadata(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.issuer = source["issuer"];
	        this.group = source["group"];
	        this.icon = source["icon"];
	        this.usageCount = source["usageCount"];
	        this.type = source["type"];
	    }
	}
	export class GroupInfo {
	    name: string;
	    icon?: string;
	
	    static createFrom(source: any = {}) {
	        return new GroupInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.icon = source["icon"];
	    }
	}

}

export namespace importer {
	
	export class ImportResult {
	    added: number;
	    skipped: number;
	    summary: string;
	    format: string;
	
	    static createFrom(source: any = {}) {
	        return new ImportResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.added = source["added"];
	        this.skipped = source["skipped"];
	        this.summary = source["summary"];
	        this.format = source["format"];
	    }
	}

}

export namespace main {
	
	export class BackupSettings {
	    dir: string;
	    schedule: string;
	    retention: string;
	    lastBackup: string;
	    lastError: string;
	
	    static createFrom(source: any = {}) {
	        return new BackupSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dir = source["dir"];
	        this.schedule = source["schedule"];
	        this.retention = source["retention"];
	        this.lastBackup = source["lastBackup"];
	        this.lastError = source["lastError"];
	    }
	}
	export class URIPreview {
	    type: string;
	    issuer: string;
	    name: string;
	    secret: string;
	    algo: string;
	    digits: number;
	    period: number;
	    counter: number;
	
	    static createFrom(source: any = {}) {
	        return new URIPreview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.issuer = source["issuer"];
	        this.name = source["name"];
	        this.secret = source["secret"];
	        this.algo = source["algo"];
	        this.digits = source["digits"];
	        this.period = source["period"];
	        this.counter = source["counter"];
	    }
	}

}

export namespace totp {
	
	export class Entry {
	    UUID: string;
	    Name: string;
	    Issuer: string;
	    Secret: string;
	    Algo: string;
	    Digits: number;
	    Period: number;
	    Type: string;
	    Counter: number;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.UUID = source["UUID"];
	        this.Name = source["Name"];
	        this.Issuer = source["Issuer"];
	        this.Secret = source["Secret"];
	        this.Algo = source["Algo"];
	        this.Digits = source["Digits"];
	        this.Period = source["Period"];
	        this.Type = source["Type"];
	        this.Counter = source["Counter"];
	    }
	}

}

export namespace vaultctrl {
	
	export class VaultStatus {
	    enabled: boolean;
	    unlocked: boolean;
	
	    static createFrom(source: any = {}) {
	        return new VaultStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.unlocked = source["unlocked"];
	    }
	}

}

