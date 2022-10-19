using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzTokenFinder
{
    public class TBStorageObject
    {
        public Tbdatastoreobject TBDataStoreObject { get; set; }
    }

    public class Tbdatastoreobject
    {
        public Header Header { get; set; }
        public Objectdata ObjectData { get; set; }
    }

    public class Header
    {
        public string ObjectType { get; set; }
        public int SchemaVersionMajor { get; set; }
        public int SchemaVersionMinor { get; set; }
    }

    public class Objectdata
    {
        public Systemdefinedproperties SystemDefinedProperties { get; set; }
        public object[] ProviderDefinedProperties { get; set; }
        public Perapplicationproperties PerApplicationProperties { get; set; }
    }

    public class Systemdefinedproperties
    {
        public Requestindex RequestIndex { get; set; }
        public Expiration Expiration { get; set; }
        public Status Status { get; set; }
        public Responsebytes ResponseBytes { get; set; }
        public Providerpfn ProviderPfn { get; set; }
    }

    public class Requestindex
    {
        public string Type { get; set; }
        public bool IsProtected { get; set; }
        public string Value { get; set; }
    }

    public class Expiration
    {
        public string Type { get; set; }
        public bool IsProtected { get; set; }
        public string Value { get; set; }
    }

    public class Status
    {
        public string Type { get; set; }
        public bool IsProtected { get; set; }
        public string Value { get; set; }
    }

    public class Responsebytes
    {
        public string Type { get; set; }
        public bool IsProtected { get; set; }
        public string Value { get; set; }
    }

    public class Providerpfn
    {
        public string Type { get; set; }
        public bool IsProtected { get; set; }
        public string Value { get; set; }
    }

    public class Perapplicationproperties
    {
    }

}
