// Sample model file
// Add your database models here

class SampleModel {
    constructor(data) {
        this.id = data.id || Date.now();
        this.name = data.name || '';
        this.createdAt = new Date();
    }

    static findAll() {
        return [];
    }

    static findById(id) {
        return null;
    }
}

module.exports = SampleModel;
