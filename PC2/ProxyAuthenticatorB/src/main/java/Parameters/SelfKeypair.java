package Parameters;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;


public class SelfKeypair {
    public Element y;
    public Element Y;
    public SelfKeypair(Field Z_phat, Element g_solid){
        this.y = Z_phat.newRandomElement().getImmutable();
        this.Y = g_solid.pow(y.toBigInteger()).getImmutable();
    }
}
