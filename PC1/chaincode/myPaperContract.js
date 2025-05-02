'use strict';


const { verify } = require('crypto');
const {Contract} = require('fabric-contract-api');

class MyPaperContract extends Contract {
    constructor(){
        // Unique namespace when multiple contracts per chaincode file
        super('MyPaperContract');
    }

    /**
     * Instantiate to perform any setup of the ledger that might be required.
     * @param {Context} ctx the transaction context
     */
    async InitLedger(ctx) {
        // No implementation required with this example
        // It could be where data migration is performed, if necessary
        console.log('Instantiate the contract');
    }

    async InfoExists(ctx, id){
        const infoJSON = await ctx.stub.getState(id);
        return infoJSON && infoJSON.length > 0;
    }

    async DeleteInfo(ctx, id){
        const exists = await this.InfoExists(ctx, id);
        if(!exists){
            throw new Error(`The info of ${id} does not exist`);
        }
        return ctx.stub.deleteState(id);
    }

    
    async UpdateInfo(ctx, id, info){
        const exists = await this.InfoExists(ctx, id);
        if(exists){
            //await this.DeleteInfo(ctx, id);
            return 'false';
        }
        await ctx.stub.putState(id, Buffer.from(info));
        return 'true';
    }

    async UpdateState(ctx, id){
        var info = {"verify":"0"};
        const exists = await this.InfoExists(ctx, id);
        if(exists){
            const infoJSON = await ctx.stub.getState(id);
            info = JSON.parse(infoJSON.toString());
            // info["verify"]++;
            const intStr = parseInt(info["verify"], 10);
            info["verify"] = (intStr+1).toString();
            //await this.DeleteInfo(ctx, id);
        }
        await ctx.stub.putState(id, Buffer.from(JSON.stringify(info)));
        return 'true';
    }


    async QueryInfo(ctx, id){
        const infoJSON = await ctx.stub.getState(id);
        if( !infoJSON || infoJSON.length == 0){
            throw new Error('The info of ${id} does not exist');
        }
        return infoJSON.toString();
    }
}

module.exports = MyPaperContract;
